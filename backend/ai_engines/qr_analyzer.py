import cv2
from pyzbar.pyzbar import decode
from PIL import Image
import numpy as np
from io import BytesIO

from ai_engines.url_analyzer import analyze_url
from ai_engines.url_utils import extract_urls_from_text, normalize_url
from ai_engines.nlp_analyzer import analyze_text_for_scam


def _preprocess_for_decode(image_array):
    """Try multiple preprocessing passes to improve QR decode rate."""
    variants = [image_array]

    if len(image_array.shape) == 3:
        gray = cv2.cvtColor(image_array, cv2.COLOR_BGR2GRAY)
    else:
        gray = image_array

    variants.append(gray)

    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    _, thresh = cv2.threshold(blurred, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(thresh)

    adaptive = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
    )
    variants.append(adaptive)

    h, w = gray.shape[:2]
    if max(h, w) < 800:
        scale = 800 / max(h, w)
        upscaled = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)
        variants.append(upscaled)

    return variants


def _decode_all_qr_codes(image_array):
    seen = set()
    results = []
    for variant in _preprocess_for_decode(image_array):
        for obj in decode(variant):
            try:
                data = obj.data.decode('utf-8')
            except UnicodeDecodeError:
                data = obj.data.decode('latin-1', errors='replace')
            if data not in seen:
                seen.add(data)
                results.append(data)
        if results:
            break
    return results


def _analyze_payload(qr_data):
    qr_lower = qr_data.lower().strip()

    if qr_lower.startswith(('http://', 'https://')):
        url_analysis = analyze_url(qr_data)
        return {
            'type': 'URL',
            'extracted_data': qr_data,
            'analysis': url_analysis,
        }

    urls_in_text = extract_urls_from_text(qr_data)
    if urls_in_text:
        primary_url = urls_in_text[0]
        url_analysis = analyze_url(normalize_url(primary_url))
        url_analysis['details'].insert(0, f'Hidden URL detected in QR text: {primary_url}')
        if len(urls_in_text) > 1:
            url_analysis['details'].append(f'Additional URLs found: {", ".join(urls_in_text[1:])}')
        return {
            'type': 'Hidden URL',
            'extracted_data': qr_data,
            'detected_urls': urls_in_text,
            'analysis': url_analysis,
        }

    if qr_lower.startswith('upi://') or 'upi://pay' in qr_lower:
        return {
            'type': 'UPI Payment',
            'extracted_data': qr_data,
            'analysis': {
                'trust_score': 55,
                'danger_score': 45,
                'risk_level': 'Medium',
                'details': [
                    'UPI payment QR detected. Always verify receiver name and amount before paying.',
                    'Never scan UPI QR codes from unknown sources or unsolicited messages.',
                ],
            },
        }

    if qr_lower.startswith('wifi:'):
        return {
            'type': 'WiFi Network',
            'extracted_data': qr_data,
            'analysis': {
                'trust_score': 70,
                'danger_score': 30,
                'risk_level': 'Low',
                'details': ['WiFi configuration QR. Ensure you trust the network owner before connecting.'],
            },
        }

    if qr_lower.startswith('tel:') or qr_lower.startswith('sms:'):
        return {
            'type': 'Contact Action',
            'extracted_data': qr_data,
            'analysis': {
                'trust_score': 60,
                'danger_score': 40,
                'risk_level': 'Medium',
                'details': ['Phone/SMS action QR. Verify the source before calling or texting.'],
            },
        }

    text_analysis = analyze_text_for_scam(qr_data)
    trust_score = max(0, 100 - text_analysis['scam_probability'])
    return {
        'type': 'Text',
        'extracted_data': qr_data,
        'analysis': {
            'trust_score': trust_score,
            'danger_score': text_analysis['scam_probability'],
            'risk_level': text_analysis['risk_level'],
            'details': text_analysis['findings'] or ['Plain text QR — no obvious scam patterns detected.'],
        },
    }


def analyze_qr(image_bytes):
    try:
        pil_image = Image.open(BytesIO(image_bytes))
        open_cv_image = np.array(pil_image)
        if len(open_cv_image.shape) == 3:
            open_cv_image = open_cv_image[:, :, ::-1].copy()

        decoded_list = _decode_all_qr_codes(open_cv_image)

        if not decoded_list:
            return {
                'success': False,
                'message': 'No QR code detected. Try a clearer image or crop tightly around the QR code.',
            }

        primary = _analyze_payload(decoded_list[0])
        result = {
            'success': True,
            'qr_count': len(decoded_list),
            **primary,
        }

        if len(decoded_list) > 1:
            result['additional_qr_codes'] = decoded_list[1:]
            result['analysis']['details'].append(
                f'Warning: {len(decoded_list)} QR codes found in image — verify you scanned the intended one.'
            )

        return result

    except Exception as e:
        return {
            'success': False,
            'message': f'Error processing image: {str(e)}',
        }
