from flask import Blueprint, request, jsonify
from ai_engines.url_analyzer import analyze_url
from ai_engines.qr_analyzer import analyze_qr
from ai_engines.nlp_analyzer import analyze_text_for_scam
from models import db, ScanHistory
import json

scan_bp = Blueprint('scan', __name__)


def _danger_score(analysis, scan_type):
    if scan_type == 'TEXT':
        return analysis.get('danger_score', analysis.get('scam_probability', 0))
    return analysis.get('danger_score', 100 - analysis.get('trust_score', 50))


@scan_bp.route('/url', methods=['POST'])
def scan_url():
    data = request.json or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    analysis_result = analyze_url(url)

    scan_record = ScanHistory(
        scan_type='URL',
        target=url,
        risk_score=_danger_score(analysis_result, 'URL'),
        risk_level=analysis_result['risk_level'],
        details=json.dumps(analysis_result['details']),
    )
    db.session.add(scan_record)
    db.session.commit()

    return jsonify(analysis_result)


@scan_bp.route('/url/batch', methods=['POST'])
def scan_url_batch():
    """Scan multiple URLs at once."""
    data = request.json or {}
    urls = data.get('urls', [])

    if not urls or not isinstance(urls, list):
        return jsonify({'error': 'Provide a list of URLs in "urls" field'}), 400

    results = []
    for url in urls[:20]:
        url = url.strip()
        if not url:
            continue
        analysis = analyze_url(url)
        results.append({'url': url, **analysis})

        scan_record = ScanHistory(
            scan_type='URL',
            target=url,
            risk_score=_danger_score(analysis, 'URL'),
            risk_level=analysis['risk_level'],
            details=json.dumps(analysis['details']),
        )
        db.session.add(scan_record)

    db.session.commit()
    return jsonify({'count': len(results), 'results': results})


@scan_bp.route('/qr', methods=['POST'])
def scan_qr():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    image_bytes = file.read()
    analysis_result = analyze_qr(image_bytes)

    if analysis_result.get('success') and 'analysis' in analysis_result:
        scan_record = ScanHistory(
            scan_type='QR',
            target=analysis_result.get('extracted_data', 'Unknown')[:500],
            risk_score=_danger_score(analysis_result['analysis'], 'QR'),
            risk_level=analysis_result['analysis'].get('risk_level', 'Unknown'),
            details=json.dumps(analysis_result['analysis'].get('details', [])),
        )
        db.session.add(scan_record)
        db.session.commit()

    return jsonify(analysis_result)


@scan_bp.route('/text', methods=['POST'])
def scan_text():
    data = request.json or {}
    text = data.get('text', '').strip()

    if not text:
        return jsonify({'error': 'Text is required'}), 400

    analysis_result = analyze_text_for_scam(text)

    scan_record = ScanHistory(
        scan_type='TEXT',
        target=text[:50] + '...' if len(text) > 50 else text,
        risk_score=_danger_score(analysis_result, 'TEXT'),
        risk_level=analysis_result['risk_level'],
        details=json.dumps(analysis_result['findings']),
    )
    db.session.add(scan_record)
    db.session.commit()

    return jsonify(analysis_result)


@scan_bp.route('/history', methods=['GET'])
def get_history():
    limit = min(int(request.args.get('limit', 10)), 100)
    recent_scans = ScanHistory.query.order_by(ScanHistory.timestamp.desc()).limit(limit).all()
    history = []
    for scan in recent_scans:
        history.append({
            'id': scan.id,
            'type': scan.scan_type,
            'target': scan.target,
            'danger_score': scan.risk_score,
            'risk_level': scan.risk_level,
            'timestamp': scan.timestamp.isoformat(),
        })
    return jsonify({'history': history})
