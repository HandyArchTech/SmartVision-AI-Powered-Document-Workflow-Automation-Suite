"""
SmartVision: AI-Powered Document Workflow Automation Suite

This is a feature-rich Python system that performs:
- Automated document scanning (image to searchable PDF)
- OCR (Optical Character Recognition) for multi-language support
- Data extraction (tables, key-values, signatures, images)
- Document redaction (PII, emails, phone numbers, etc)
- Advanced PDF manipulation (merge, split, reorder, digital-sign, watermark)
- Auto-file labeling, tagging, search, and export
- Batch processing via GUI and Command Line
- REST API server for integration
- Configurable rules and templates for different document types

Perfect for small law offices, accountants, realtors, notaries, labs, and admins.

Built to be extensible, with multiple plugin-points.

Requires:
Python 3.8+, tesseract-ocr installed, poppler-utils, ghostscript

Modules required: Pillow, pytesseract, pdfplumber, opencv-python, PyPDF2, flask, watchdog, numpy, pandas, pdf2image, reportlab, pdfminer.six, chardet, requests

"""

import os
import re
import sys
import io
import time
import threading
import uuid
import json
import shutil
import tempfile
import logging
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Union, Optional

import cv2
import numpy as np
from PIL import Image
import pytesseract
import pandas as pd
import pdfplumber
from PyPDF2 import PdfFileReader, PdfFileWriter, PdfMerger
from pdf2image import convert_from_path
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from flask import Flask, request, jsonify, send_file
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

###############################
# Logging Setup
###############################

def setup_logging(log_file="smartvision.log"):
    logger = logging.getLogger("SmartVision")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(log_file)
    ch = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

logger = setup_logging()

###############################
# 1. IMAGE PREPROCESSING SUITE
###############################

def preprocess_image(image: np.ndarray) -> np.ndarray:
    """Clean/deskew/binarize/denoise the given image for best OCR results."""
    try:
        logger.info("Starting image preprocessing...")
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        # Deskew with moments
        coords = np.column_stack(np.where(gray > 0))
        angle = cv2.minAreaRect(coords)[-1]
        if angle < -45:
            angle = -(90 + angle)
        else:
            angle = -angle
        (h, w) = gray.shape[:2]
        center = (w // 2, h // 2)
        M = cv2.getRotationMatrix2D(center, angle, 1.0)
        deskewed = cv2.warpAffine(gray, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
        # Adaptive thresholding
        threshed = cv2.adaptiveThreshold(deskewed, 255,
                                         cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                         cv2.THRESH_BINARY, 31, 10)
        # Denoising
        denoised = cv2.fastNlMeansDenoising(threshed, None, 30, 7, 21)
        logger.info("Image preprocessing complete.")
        return denoised
    except Exception as ex:
        logger.error(f"Error during image preprocessing: {ex}")
        return image

def load_image(filepath: str) -> np.ndarray:
    """Load image file (any format) into numpy array."""
    image = cv2.imdecode(np.fromfile(filepath, dtype=np.uint8), cv2.IMREAD_COLOR)
    return image

###############################
# 2. OCR & DOCUMENT DIGITIZATION
###############################

def perform_ocr(image: np.ndarray, lang='eng') -> str:
    """Run OCR on preprocessed image"""
    try:
        logger.info("Performing OCR...")
        pil_image = Image.fromarray(image)
        text = pytesseract.image_to_string(pil_image, lang=lang)
        logger.info("OCR complete.")
        return text
    except Exception as ex:
        logger.error(f"OCR failed: {ex}")
        return ""

def extract_tables(image: np.ndarray, lang='eng') -> List[Dict]:
    """Try to extract tables from image using OCR and openCV."""
    try:
        logger.info("Extracting tables from image...")
        result_tables = []
        # Use pdfplumber separate logic for PDFs
        pil_img = Image.fromarray(image)
        data = pytesseract.image_to_data(pil_img, lang=lang, output_type=pytesseract.Output.DATAFRAME)
        # Very naive, better for printed PDFs
        boxes = []
        for idx, row in data.iterrows():
            if not pd.isna(row['text']) and len(str(row['text']).strip()) > 0:
                x, y, w, h = row['left'], row['top'], row['width'], row['height']
                boxes.append((x, y, x + w, y + h))
        # TODO: Improve table detection
        if boxes:
            result_tables.append({
                "cells": boxes,
                "text": data.to_dict('records')
            })
        logger.info("Table extraction from image complete.")
        return result_tables
    except Exception as ex:
        logger.error(f"Table extraction failed: {ex}")
        return []

def ocr_pdf(input_pdf: str, output_pdf: Optional[str]=None, lang='eng') -> str:
    """Read a PDF (scanned or born digital), OCR each page if needed, and save/searchable PDF."""
    temp_dir = tempfile.mkdtemp()
    try:
        logger.info(f"Converting PDF to images: {input_pdf}")
        image_list = convert_from_path(input_pdf, output_folder=temp_dir, fmt='png', dpi=300)
        full_text = ""
        pdf_writer = PdfFileWriter()
        for i, img in enumerate(image_list):
            np_img = np.array(img)
            pre_img = preprocess_image(np_img)
            text = perform_ocr(pre_img, lang=lang)
            full_text += f"--- Page {i+1}\n{text}\n"
            pdf_img_stream = io.BytesIO()
            img.save(pdf_img_stream, format='PNG')
            pdf_img_stream.seek(0)
            # Create a single-page PDF with the image
            temp_pdf_path = os.path.join(temp_dir, f"page_{i}.pdf")
            c = canvas.Canvas(temp_pdf_path, pagesize=letter)
            rl_img = Image.fromarray(pre_img)
            img_temp = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
            rl_img.save(img_temp, format='PNG')
            img_temp.close()
            c.drawImage(img_temp.name, 0, 0, width=letter[0], height=letter[1])
            c.showPage()
            c.save()
            with open(temp_pdf_path, 'rb') as pf:
                page_pdf = PdfFileReader(pf).getPage(0)
                pdf_writer.addPage(page_pdf)
            os.remove(img_temp.name)
        if output_pdf:
            with open(output_pdf, 'wb') as out_f:
                pdf_writer.write(out_f)
        shutil.rmtree(temp_dir)
        logger.info(f"OCR for PDF {input_pdf} complete.")
        return full_text
    except Exception as ex:
        logger.error(f"OCR PDF failed: {ex}")
        return ""
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def pdf_to_text(input_pdf: str) -> str:
    """Extract all text from a PDF, using pdfplumber on extracted images if needed."""
    try:
        text = ""
        with pdfplumber.open(input_pdf) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text() or ""
                text += page_text + "\n"
        return text
    except Exception as ex:
        logger.error(f"pdf_to_text error: {ex}")
        return ""

###############################
# 3. DATA EXTRACTION TOOLS
###############################

def extract_keyvalues(text: str, fields: dict) -> dict:
    """
    Extract key-values from OCR text based on templates.
    fields: dict mapping display name to regex pattern, e.g.
      { "DATE": r"Date\s*[:\-]\s*(\d{4}-\d{2}-\d{2})" }
    """
    results = {}
    for field, pattern in fields.items():
        match = re.search(pattern, text, flags=re.IGNORECASE)
        results[field] = match.group(1) if match else ""
    return results

def extract_emails(text: str) -> List[str]:
    """Extract all emails from document."""
    return list(set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)))

def extract_phones(text: str) -> List[str]:
    """Extract all phone numbers from document."""
    return list(set(re.findall(r'(\+?\d[\d\-\(\) ]{7,}\d)', text)))

def extract_dates(text: str) -> List[str]:
    # ISO, US, EU
    date_pats = [
        r'(\d{4}-\d{2}-\d{2})',
        r'(\d{1,2}/\d{1,2}/\d{2,4})',
        r'(\d{1,2}\.\d{1,2}\.\d{2,4})',
    ]
    dates = []
    for pat in date_pats:
        dates.extend(re.findall(pat, text))
    return list(set(dates))

def extract_signatures(image: np.ndarray) -> List[Tuple[int,int,int,int]]:
    """Attempt to locate signature regions using contour and color heuristics."""
    try:
        # Assume blue/black ink signatures
        logger.info("Extracting signatures...")
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        # Remove light areas (documents), keep dark ink
        _, binary = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY_INV)
        contours, _h = cv2.findContours(binary, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        sig_boxes = []
        for c in contours:
            x, y, w, h = cv2.boundingRect(c)
            if w > 60 and h > 15 and w*h < image.shape[0]*image.shape[1]*0.05:
                sig_boxes.append((x, y, w, h))
        logger.info(f"Signature extraction found {len(sig_boxes)} candidates.")
        return sig_boxes
    except Exception as ex:
        logger.error(f"extract_signatures failed: {ex}")
        return []

###############################
# 4. PDF MANIPULATION SUITE
###############################

def merge_pdfs(input_pdfs: List[str], output_pdf: str):
    logger.info(f"Merging PDFs: {input_pdfs} -> {output_pdf}")
    merger = PdfMerger()
    for pdf in input_pdfs:
        merger.append(pdf)
    merger.write(output_pdf)
    merger.close()

def split_pdf(input_pdf: str, output_pattern: str) -> List[str]:
    """Splits a PDF into single-page PDFs. output_pattern should contain %d."""
    logger.info(f"Splitting PDF {input_pdf} with pattern {output_pattern}")
    pdf = PdfFileReader(open(input_pdf, 'rb'))
    outputs = []
    for i in range(pdf.getNumPages()):
        writer = PdfFileWriter()
        writer.addPage(pdf.getPage(i))
        out_name = output_pattern % (i+1)
        with open(out_name, 'wb') as out_f:
            writer.write(out_f)
        outputs.append(out_name)
    return outputs

def reorder_pdf(input_pdf: str, page_order: List[int], output_pdf: str):
    pdf_reader = PdfFileReader(open(input_pdf, 'rb'))
    pdf_writer = PdfFileWriter()
    for i in page_order:
        pdf_writer.addPage(pdf_reader.getPage(i))
    with open(output_pdf, 'wb') as out_f:
        pdf_writer.write(out_f)

def add_watermark(input_pdf: str, watermark_pdf: str, output_pdf: str):
    logger.info(f"Adding watermark from {watermark_pdf}")
    original = PdfFileReader(open(input_pdf, 'rb'))
    watermark = PdfFileReader(open(watermark_pdf, 'rb')).getPage(0)
    writer = PdfFileWriter()
    for i in range(original.getNumPages()):
        page = original.getPage(i)
        page.mergePage(watermark)
        writer.addPage(page)
    with open(output_pdf, 'wb') as out_f:
        writer.write(out_f)

def redact_pdf(input_pdf: str, output_pdf: str, patterns: List[str]):
    """
    Redact all matching patterns (email, phone, PII) in the PDF.
    """
    logger.info(f"Redacting {patterns} in {input_pdf}")
    with pdfplumber.open(input_pdf) as pdf, open(output_pdf, 'wb') as out_f:
        pdf_writer = PdfFileWriter()
        for page in pdf.pages:
            page_image = page.to_image()
            text = page.extract_text()
            for pat in patterns:
                for m in re.finditer(pat, text):
                    bbox = page.bbox  # TODO: use layout objects to crop coordinates
                    page_image.draw_rect((bbox[0], bbox[1], bbox[2], bbox[3]), fill=(0,0,0,127))
            temp_img = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
            page_image.save(temp_img.name, format="PNG")
            temp_pdf = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
            c = canvas.Canvas(temp_pdf.name, pagesize=letter)
            c.drawImage(temp_img.name, 0, 0, width=letter[0], height=letter[1])
            c.showPage()
            c.save()
            temp_pdf.seek(0)
            pdf_writer.addPage(PdfFileReader(open(temp_pdf.name, 'rb')).getPage(0))
            os.remove(temp_img.name)
            os.remove(temp_pdf.name)
        pdf_writer.write(out_f)

def add_digital_signature(input_pdf: str, signer: str, output_pdf: str):
    """Just add a visible signature block (not PKI) for visual acknowledgement"""
    logger.info(f"Adding signature by {signer} to {input_pdf}")
    with open(input_pdf, 'rb') as inf:
        reader = PdfFileReader(inf)
        writer = PdfFileWriter()
        for p in range(reader.getNumPages()):
            page = reader.getPage(p)
            if p == reader.getNumPages() - 1:
                # Add signature block overlay
                c = canvas.Canvas('sigtemp.pdf', pagesize=letter)
                c.drawString(100, 80, f"Signed by: {signer} at {datetime.datetime.now()}")
                c.save()
                sig_page = PdfFileReader(open('sigtemp.pdf', 'rb')).getPage(0)
                page.mergePage(sig_page)
                os.remove('sigtemp.pdf')
            writer.addPage(page)
        with open(output_pdf, 'wb') as outf:
            writer.write(outf)

###############################
# 5. AUTO-FILING AND TAGGING
###############################

def auto_label_file(text: str, extracted: Dict) -> str:
    """
    Suggest a smart filename based on document content and extracted metadata.
    """
    filename = ""
    if 'DATE' in extracted and extracted['DATE']:
        filename += extracted['DATE']
    if 'NAME' in extracted and extracted['NAME']:
        filename += "-" + extracted['NAME']
    emails = extract_emails(text)
    if emails:
        filename += "-email"
    filename = re.sub(r'\W+', '_', filename)
    filename = filename.strip('_') or "ScannedDoc"
    return filename

def auto_tag(text: str, extracted: Dict) -> List[str]:
    tags = []
    keywords = {'invoice': 'INVOICE', 'receipt':'RECEIPT', 'signed':'SIGNED'}
    for k, v in keywords.items():
        if k in text.lower():
            tags.append(v)
    if 'DATE' in extracted and extracted['DATE']:
        tags.append('DATED')
    return tags

###############################
# 6. BATCH/JOB MANAGEMENT
###############################

class BatchJob:
    """A job for batch processing files."""
    def __init__(self, files: List[str], outdir: str, lang='eng', rules: dict={}):
        self.files = files
        self.outdir = outdir
        self.lang = lang
        self.rules = rules
        self.id = str(uuid.uuid4())
        self.results = []
        self.status = "INIT"

    def run(self):
        logger.info(f"BatchJob {self.id} running...")
        self.status = "RUNNING"
        for file in self.files:
            try:
                result = process_document(file, self.outdir, self.lang, self.rules)
                self.results.append(result)
            except Exception as ex:
                logger.error(f"Batch process error: {ex}")
        self.status = "DONE"
        logger.info(f"BatchJob {self.id} complete.")

###############################
# 7. GUI FRONTEND (Tkinter)
###############################

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    GUI_AVAILABLE = True
except Exception as ex:
    logger.warning("GUI/Tkinter unavailable.")
    GUI_AVAILABLE = False

class SmartVisionGUI:
    def __init__(self, master):
        self.master = master
        master.title("SmartVision Document Automation Suite")
        master.geometry("880x600")
        self.in_files = []
        self.rules = {}
        self.setup_gui()

    def setup_gui(self):
        self.select_btn = tk.Button(self.master, text="Select Files", command=self.load_files)
        self.select_btn.pack()
        self.lang_var = tk.StringVar(value="eng")
        
        self.lang_label = tk.Label(self.master, text="OCR Language (Tesseract code):")
        self.lang_label.pack()
        self.lang_entry = tk.Entry(self.master, textvariable=self.lang_var)
        self.lang_entry.pack()
        
        self.start_btn = tk.Button(self.master, text="Run Batch", command=self.run_batch)
        self.start_btn.pack()
        
        self.progress = ttk.Progressbar(self.master, orient=tk.HORIZONTAL, length=500, mode='determinate')
        self.progress.pack()
        
        self.log_box = tk.Text(self.master, height=20, width=100)
        self.log_box.pack()

    def log(self, txt):
        self.log_box.insert(tk.END, txt + "\n")
        self.log_box.see(tk.END)

    def load_files(self):
        files = filedialog.askopenfilenames(title="Select files", filetypes=(("Images and PDFs", "*.pdf;*.png;*.jpg;*.jpeg;*.tif"),))
        self.in_files = files
        self.log(f"Selected files: {self.in_files}")

    def run_batch(self):
        if not self.in_files:
            messagebox.showerror("No files!", "Please select at least one file.")
            return
        lang = self.lang_var.get()
        job = BatchJob(list(self.in_files), os.getcwd(), lang, self.rules)
        def job_thread():
            job.run()
            self.progress['value'] = 100
            self.log(f"Batch Done. Reports saved in {os.getcwd()}")
        threading.Thread(target=job_thread, daemon=True).start()
        for i in range(100):
            time.sleep(0.1)
            self.progress['value'] = i+1
            self.master.update_idletasks()

###############################
# 8. MAIN LOGIC/WORKFLOW
###############################

def process_document(filepath: str, outdir: str, lang='eng', rules: dict={}) -> dict:
    """Process a single document: scan, ocr, extract, organize."""
    logger.info(f"Processing document {filepath}")
    out = {"source": filepath, "success": False}
    fname, ext = os.path.splitext(os.path.basename(filepath))
    try:
        if ext.lower() in [".pdf"]:
            ocrtext = pdf_to_text(filepath)
            if not ocrtext.strip():
                ocrtext = ocr_pdf(filepath, None, lang)
            extracted = extract_keyvalues(ocrtext, rules.get('fields', {}))
            autosuggest = auto_label_file(ocrtext, extracted)
            outpath = os.path.join(outdir, autosuggest + ".pdf")
            shutil.copy(filepath, outpath)
            out['out_pdf'] = outpath
            out['extracted'] = extracted
            out['text'] = ocrtext
            out['tags'] = auto_tag(ocrtext, extracted)
            out['success'] = True
        elif ext.lower() in [".jpg", ".jpeg", ".png", ".tif"]:
            img = load_image(filepath)
            pre_img = preprocess_image(img)
            text = perform_ocr(pre_img, lang)
            extracted = extract_keyvalues(text, rules.get('fields', {}))
            # Save as PDF
            img_pil = Image.fromarray(pre_img)
            pdf_out_path = os.path.join(outdir, auto_label_file(text, extracted) + ".pdf")
            img_pil.save(pdf_out_path, "PDF")
            out['out_pdf'] = pdf_out_path
            out['extracted'] = extracted
            out['text'] = text
            out['tags'] = auto_tag(text, extracted)
            out['success'] = True
        else:
            logger.warning(f"Unsupported file extension: {filepath}")
    except Exception as ex:
        logger.error(f"process_document error: {ex}")
    return out

###############################
# 9. API SERVER (Flask)
###############################

app = Flask(__name__)

@app.route('/process', methods=['POST'])
def api_process():
    """
    POST a file with optional 'lang', 'fields' (JSON: {Name:pattern}),
    Returns: JSON with extracted data, suggested filename, tags and saved PDF.
    """
    f = request.files['file']
    lang = request.form.get('lang', 'eng')
    rules_raw = request.form.get('fields', '{}')
    try:
        rules = json.loads(rules_raw)
    except Exception:
        rules = {}
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(f.filename)[1])
    f.save(tf.name)
    outdir = tempfile.mkdtemp()
    result = process_document(tf.name, outdir, lang, {'fields':rules})
    with open(result.get('out_pdf', tf.name), 'rb') as pf:
        pdf_data = pf.read()
    resp = {
        'extracted': result.get('extracted',{}),
        'tags': result.get('tags',[]),
        'text': result.get('text',""),
        'file': os.path.basename(result.get('out_pdf', tf.name))
    }
    response_pdf = io.BytesIO(pdf_data)
    response_pdf.seek(0)
    shutil.move(result.get('out_pdf', tf.name), os.path.join(outdir, resp['file']))
    resp['pdf_path'] = os.path.join(outdir, resp['file'])
    return jsonify(resp)

@app.route('/download/<path:filename>', methods=['GET'])
def api_download(filename):
    # Download file from temp output folder
    abs_path = os.path.abspath(filename)
    return send_file(abs_path, attachment_filename=os.path.basename(filename), as_attachment=True)

###############################
# 10. FILESYSTEM WATCHER (HOTFOLDER)
###############################

class HotfolderHandler(FileSystemEventHandler):
    """Watches a directory for new files and processes them."""
    def __init__(self, in_dir, out_dir, lang='eng'):
        self.in_dir = in_dir
        self.out_dir = out_dir
        self.lang = lang
        super().__init__()

    def on_created(self, event):
        if event.is_directory:
            return
        filepath = event.src_path
        logger.info(f"Detected new file: {filepath}")
        process_document(filepath, self.out_dir, self.lang, {})

def run_hotfolder_watch(in_dir, out_dir, lang='eng'):
    event_handler = HotfolderHandler(in_dir, out_dir, lang)
    observer = Observer()
    observer.schedule(event_handler, path=in_dir, recursive=False)
    observer.start()
    logger.info(f"Started hotfolder watch: {in_dir} -> {out_dir}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

###############################
# 11. PLUGIN SYSTEM
###############################

class PluginBase:
    """Extendable plugin hook for document post-processing."""
    def process(self, doc_data: dict) -> dict:
        """Modify or enrich document data"""
        return doc_data

_PLUGINS = []

def register_plugin(plugin):
    _PLUGINS.append(plugin)

def run_plugins(doc_data):
    for plugin in _PLUGINS:
        doc_data = plugin.process(doc_data)
    return doc_data

###############################
# 12. MAIN ENTRY POINT
###############################

def main():
    import argparse
    parser = argparse.ArgumentParser(description="SmartVision Document Automation Suite")
    parser.add_argument('--gui', action='store_true', help='Run GUI frontend')
    parser.add_argument('--api', action='store_true', help='Run API server')
    parser.add_argument('--hotfolder', metavar='IN_DIR', type=str, help='Run as hotfolder watching IN_DIR')
    parser.add_argument('--outfile', type=str, help='Output folder')
    parser.add_argument('--lang', type=str, default='eng', help='OCR language code')
    parser.add_argument('--fields', type=str, help='JSON string of template extraction fields')
    parser.add_argument('files', nargs='*', help='Files to process')
    args = parser.parse_args()
    if args.gui:
        if not GUI_AVAILABLE:
            print("Tkinter not installed! Cannot run GUI.")
            exit(1)
        root = tk.Tk()
        app = SmartVisionGUI(root)
        root.mainloop()
    elif args.api:
        app.run(host='0.0.0.0', port=8585)
    elif args.hotfolder:
        outdir = args.outfile or os.getcwd()
        run_hotfolder_watch(args.hotfolder, outdir, args.lang)
    elif args.files:
        outdir = args.outfile or os.getcwd()
        rules = {}
        if args.fields:
            try:
                rules = {'fields': json.loads(args.fields)}
            except Exception as ex:
                logger.error(f"Could not parse fields JSON: {ex}")
        job = BatchJob(args.files, outdir, args.lang, rules)
        job.run()
        print(f"Batch completed: output in {outdir}")

if __name__ == "__main__":
    main()
