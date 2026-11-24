"""Tests for the Android Dynamic Analysis PDF report and landing page."""
from unittest import mock

from django.contrib.auth.models import User
from django.template.loader import get_template
from django.test import Client, TestCase

from mobsf.DynamicAnalyzer.views.android import report_pdf
from mobsf.StaticAnalyzer.views.common.pdf import render_html_to_pdf

HASH = '0123456789abcdef0123456789abcdef'
PACKAGE = 'com.example.app'


def app_call(api, app=True):
    return {
        'api': api,
        'class': 'java.lang.Example',
        'signature': f'{api}()',
        'arguments': ['<script>alert(1)</script>'],
        'returnValue': 'ok',
        'calledFrom': 'com.example.app.Main',
        'count': 1,
        'app': app,
    }


def fake_analysis(apimon):
    """Patch every data source used by get_pdf_context."""
    domains = {
        'evil.example': {
            'bad': 'yes', 'domain_or_url': 'evil.example/x',
            'ip': '10.0.0.1', 'desc': 'test malware',
            'geolocation': {'ip': '10.0.0.1', 'country_long': 'Nowhere'}},
        'good.example': {'bad': 'no', 'geolocation': None},
    }
    run_result = {
        'urls': ['https://good.example/a'],
        'domains': domains,
        'emails': ['dev@example.com'],
        'clipboard': ['copied', ''],
        'xml': [{'file': 'shared_prefs/a.xml', 'type': 'xml'}],
        'sqlite': [{'file': 'databases/a.db', 'type': 'db'}],
        'other_files': [],
        'tls_tests': {
            'has_cleartext': True,
            'tls_misconfigured': False,
            'pin_or_transparency_bypassed': False,
            'no_tls_pin_or_transparency': True},
    }
    trackers = mock.Mock()
    trackers.get_trackers_domains_or_deps.return_value = {
        'detected_trackers': 1, 'total_trackers': 400,
        'trackers': [{'name': 'Tracker', 'categories': 'Analytics',
                      'url': 'https://reports.exodus-privacy.eu.org/'}]}
    return [
        mock.patch.object(report_pdf, 'droidmon_api_analysis',
                          return_value={}),
        mock.patch.object(report_pdf, 'apimon_analysis',
                          return_value=(apimon, [('decode', 'secret')])),
        mock.patch.object(report_pdf, 'dependency_analysis',
                          return_value={'b.dex', 'a.dex'}),
        mock.patch.object(report_pdf, 'run_analysis',
                          return_value=run_result),
        mock.patch.object(report_pdf.Trackers, 'Trackers',
                          return_value=trackers),
        mock.patch.object(report_pdf, 'get_screenshots', return_value={
            'screenshots': ['1.png'],
            'activities': {'act-0.png': 'com.example.app.Main'},
            'exported_activities': {}}),
    ]


class DynamicPdfContextTests(TestCase):

    def build_context(self, apimon):
        patches = fake_analysis(apimon)
        for p in patches:
            p.start()
        self.addCleanup(mock.patch.stopall)
        return report_pdf.get_pdf_context(HASH, PACKAGE, '/tmp/x/')

    def test_apimon_lists_only_app_calls_with_limit(self):
        limit = report_pdf.APIMON_PDF_LIMIT
        calls = [app_call(f'fw{i}', app=False) for i in range(limit + 5)]
        calls += [app_call(f'app{i}') for i in range(limit + 3)]
        ctx = self.build_context({'Crypto': calls})
        crypto = ctx['apimon']['Crypto']
        self.assertEqual(len(crypto['calls']), limit)
        self.assertTrue(all(c['app'] for c in crypto['calls']))
        self.assertEqual(crypto['app_total'], limit + 3)
        self.assertEqual(crypto['unique_total'], len(calls))

    def test_summary_counts(self):
        ctx = self.build_context({})
        self.assertEqual(ctx['bad_domains'], 1)
        self.assertEqual(ctx['tls_failed'], 2)
        self.assertEqual(ctx['clipboard'], ['copied'])
        self.assertEqual(ctx['runtime_dependencies'], ['a.dex', 'b.dex'])

    def test_template_renders_to_pdf_and_escapes(self):
        ctx = self.build_context({'Crypto': [app_call('doFinal')]})
        html = get_template('pdf/dast_report.html').render(ctx)
        self.assertIn('evil.example', html)
        self.assertIn('com.example.app.Main', html)
        self.assertNotIn('act-0.png', html)
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;', html)
        pdf = render_html_to_pdf(html)
        self.assertTrue(pdf.startswith(b'%PDF'))


class DynamicPdfViewTests(TestCase):

    def setUp(self):
        self.client = Client()

    def test_requires_login(self):
        resp = self.client.get(f'/dynamic_pdf/{HASH}/')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/login/', resp['Location'])

    def test_returns_pdf_attachment(self):
        self.client.force_login(User.objects.create_superuser('tester'))
        patches = fake_analysis({})
        patches += [
            mock.patch.object(report_pdf, 'get_package_name',
                              return_value=PACKAGE),
            mock.patch.object(report_pdf, 'is_file_exists',
                              return_value=True),
        ]
        for p in patches:
            p.start()
        self.addCleanup(mock.patch.stopall)
        resp = self.client.get(f'/dynamic_pdf/{HASH}/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp['Content-Type'], 'application/pdf')
        self.assertIn(f'dynamic_report_{HASH}.pdf',
                      resp['Content-Disposition'])
        self.assertTrue(resp.content.startswith(b'%PDF'))

    def test_rejects_post(self):
        self.client.force_login(User.objects.create_superuser('tester'))
        resp = self.client.post(f'/dynamic_pdf/{HASH}/')
        self.assertEqual(resp.status_code, 405)

    def test_missing_report_does_not_return_pdf(self):
        self.client.force_login(User.objects.create_superuser('tester'))
        with mock.patch.object(report_pdf, 'get_package_name',
                               return_value=PACKAGE):
            resp = self.client.get(f'/dynamic_pdf/{HASH}/')
        self.assertNotEqual(resp.get('Content-Type'), 'application/pdf')


class LandingPageTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.client.force_login(User.objects.create_superuser('tester'))

    def test_root_shows_recent_scans(self):
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'general/recent.html')

    def test_upload_page_moved_to_analyze(self):
        resp = self.client.get('/analyze/')
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'general/home.html')
        # Scan URLs must be absolute now that the page is not at '/'
        self.assertContains(resp, "'/' + json.analyzer")
