# -*- coding: utf_8 -*-
"""Android Dynamic Analysis PDF Report.

Ported from the security-mobile fork. Kept in its own module so the
upstream report.py stays untouched and future upstream syncs stay clean.
"""
import json
import logging
import os
from pathlib import Path
import platform

from django.conf import settings
from django.http import HttpResponse
from django.template.defaulttags import register
from django.template.loader import get_template
from django.utils import timezone
from django.views.decorators.http import require_http_methods

import mobsf.MalwareAnalyzer.views.Trackers as Trackers
from mobsf.DynamicAnalyzer.views.android.analysis import (
    get_screenshots,
    run_analysis,
)
from mobsf.DynamicAnalyzer.views.android.api_monitor import (
    framework_call_counts,
)
from mobsf.DynamicAnalyzer.views.android.operations import (
    get_package_name,
)
from mobsf.DynamicAnalyzer.views.android.tests_xposed import (
    droidmon_api_analysis,
)
from mobsf.DynamicAnalyzer.views.android.tests_frida import (
    apimon_analysis,
    dependency_analysis,
)
from mobsf.MobSF.utils import (
    is_file_exists,
    is_md5,
    key,
    malware_first,
    print_n_send_error_response,
)
from mobsf.MobSF.security import (
    sanitize_filename,
)
from mobsf.MobSF.views.authentication import (
    login_required,
)
from mobsf.StaticAnalyzer.views.common.pdf import (
    render_html_to_pdf,
)

logger = logging.getLogger(__name__)
register.filter('key', key)
register.filter('malware_first', malware_first)
ctype = 'application/json; charset=utf-8'
APIMON_PDF_LIMIT = 100


def get_pdf_context(checksum, package, app_dir):
    """Collect the dynamic analysis data shown in the PDF report."""
    tools_dir = settings.TOOLS_DIR
    droidmon = droidmon_api_analysis(app_dir, package)
    apimon, b64_strings = apimon_analysis(app_dir)
    apimon_framework = framework_call_counts(apimon)
    # The PDF lists only calls made by app code, capped per category,
    # so a noisy category cannot blow the PDF size limit.
    apimon_app = {}
    for api, calls in apimon.items():
        app_calls = [c for c in calls if isinstance(c, dict) and c.get('app')]
        apimon_app[api] = {
            'calls': app_calls[:APIMON_PDF_LIMIT],
            'app_total': len(app_calls),
            'unique_total': len(calls),
            'framework': apimon_framework.get(api, 0),
        }
    deps = dependency_analysis(package, app_dir)
    analysis_result = run_analysis(app_dir, checksum, package)
    domains = analysis_result['domains']
    trk = Trackers.Trackers(checksum, app_dir, tools_dir)
    trackers = trk.get_trackers_domains_or_deps(domains, deps)
    images = get_screenshots(checksum, settings.DWD_DIR)
    tls_tests = analysis_result['tls_tests']
    tls_failed = 0
    if tls_tests:
        tls_failed = sum(1 for k in (
            'has_cleartext',
            'tls_misconfigured',
            'pin_or_transparency_bypassed',
            'no_tls_pin_or_transparency',
        ) if tls_tests.get(k) is True)
    bad_domains = sum(
        1 for d in domains.values()
        if isinstance(d, dict) and d.get('bad') == 'yes')
    proto = 'file:///' if platform.system() == 'Windows' else 'file://'
    return {
        'hash': checksum,
        'package': package,
        'emails': analysis_result['emails'],
        'urls': analysis_result['urls'],
        'domains': domains,
        'bad_domains': bad_domains,
        'clipboard': [c for c in analysis_result['clipboard'] if c.strip()],
        'xml': analysis_result['xml'],
        'sqlite': analysis_result['sqlite'],
        'others': analysis_result['other_files'],
        'tls_tests': tls_tests,
        'tls_failed': tls_failed,
        'screenshots': images['screenshots'],
        'activity_tester': images['activities'],
        'exported_activity_tester': images['exported_activities'],
        'droidmon': droidmon,
        'apimon': apimon_app,
        'apimon_limit': APIMON_PDF_LIMIT,
        'base64_strings': b64_strings,
        'trackers': trackers,
        'runtime_dependencies': sorted(deps),
        'version': settings.MOBSF_VER,
        'title': 'Dynamic Analysis',
        'timestamp': timezone.localtime(timezone.now()),
        'base_url': proto + Path(settings.BASE_DIR).as_posix(),
        'dwd_dir': proto + Path(settings.DWD_DIR).as_posix() + '/',
    }


@login_required
@require_http_methods(['GET'])
def pdf_report(request, checksum):
    """Generate the Android Dynamic Analysis PDF report."""
    logger.info('Generating Dynamic Analysis PDF Report')
    try:
        if not is_md5(checksum):
            return print_n_send_error_response(request, 'Invalid Hash')
        package = get_package_name(checksum)
        if not package:
            return print_n_send_error_response(request, 'Invalid Parameters')
        app_dir = os.path.join(settings.UPLD_DIR, checksum + '/')
        if not is_file_exists(os.path.join(app_dir, 'logcat.txt')):
            msg = ('Dynamic Analysis report is not available '
                   'for this app. Perform Dynamic Analysis '
                   'and generate the report.')
            return print_n_send_error_response(request, msg)
        context = get_pdf_context(checksum, package, app_dir)
    except Exception as exp:
        logger.exception('Error collecting Dynamic Analysis PDF data')
        return print_n_send_error_response(
            request, f'Error Generating Dynamic Analysis PDF. {exp}')
    try:
        html = get_template('pdf/dast_report.html').render(context)
        pdf_dat = render_html_to_pdf(html)
    except Exception as exp:
        logger.exception('Error Generating Dynamic Analysis PDF Report')
        err = {'pdf_error': 'Cannot Generate PDF', 'err_details': str(exp)}
        return HttpResponse(
            json.dumps(err),  # lgtm [py/stack-trace-exposure]
            content_type=ctype,
            status=500)
    response = HttpResponse(pdf_dat, content_type='application/pdf')
    filename = sanitize_filename(f'dynamic_report_{checksum}.pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response
