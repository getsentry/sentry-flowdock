from django import forms
from django.conf import settings
from django.utils.safestring import mark_safe

from sentry.plugins.bases.notify import NotifyPlugin
from sentry.web.helpers import render_to_string

import sentry_flowdock
import json
import logging
import urllib2


class FlowdockOptionsForm(forms.Form):
    token = forms.CharField(help_text='Your flow API token.')


class FlowdockMessage(NotifyPlugin):
    author = 'Sentry Team'
    author_url = 'https://github.com/getsentry/sentry-flowdock'
    version = sentry_flowdock.VERSION
    description = 'Event notification to Flowdock.'
    resource_links = [
        ('Bug Tracker', 'https://github.com/getsentry/sentry-flowdock/issues'),
        ('Source', 'https://github.com/getsentry/sentry-flowdock'),
    ]
    slug = 'flowdock'
    title = 'Flowdock'
    conf_title = title
    conf_key = 'flowdock'
    project_conf_form = FlowdockOptionsForm

    logger = logging.getLogger('sentry.errors')
    base_url = 'https://api.flowdock.com/v1/messages/team_inbox/{token}'

    def is_configured(self, project):
        return all((self.get_option(k, project) for k in ('token',)))

    def on_alert(self, alert, **kwargs):
        project = alert.project
        token = self.get_option('token', project)

        subject = '[{0}] ALERT: {1}'.format(
            project.name.encode('utf-8'),
            alert.message.encode('utf-8')[:50],
        )

        message = render_to_string('sentry_flowdock/alert.html', {
            'alert': alert,
        })

        self.send_payload(
            token=token,
            subject=subject,
            message=message,
            link=alert.get_absolute_url(),
        )

    def post_process(self, group, event, is_new, is_sample, **kwargs):
        if not is_new:
            return

        project = group.project
        token = self.get_option('token', project)

        subject = '[%s] %s: %s' % (
            project.name.encode('utf-8'),
            unicode(group.get_level_display()).upper().encode('utf-8'),
            event.error().encode('utf-8').splitlines()[0])

        interface_list = []
        for interface in event.interfaces.itervalues():
            body = interface.to_email_html(event)
            if not body:
                continue
            interface_list.append((interface.get_title(), mark_safe(body)))

        message = render_to_string('sentry_flowdock/event.html', {
            'group': group,
            'event': event,
            'link': 'http://example.com/link',
            'interfaces': interface_list,
            'tags': event.get_tags(),
        })

        self.send_payload(
            token=token,
            subject=subject,
            message=message,
            link=group.get_absolute_url(),
        )

    def send_payload(self, token, subject, message, link):
        url = self.base_url.format(token=token)

        context = {
            'source': 'Sentry',
            'from_address': settings.DEFAULT_FROM_EMAIL,
            'from_name': "Sentry",
            'subject': subject,
            'content': message,
            'link': link,
        }

        body = json.dumps(context)

        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'sentry-flowdock/%s' % (self.version,),
        }

        request = urllib2.Request(url, headers=headers)
        try:
            urllib2.urlopen(request, body)
        except urllib2.HTTPError as e:
            self.logger.exception('Unexpected response from Flowdock: %s', e.read())
