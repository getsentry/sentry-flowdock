# -*- coding: utf-8 -*-
"""tasks.py: Django core"""

from __future__ import unicode_literals
from __future__ import print_function

import re
import json
import logging
import urllib

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.safestring import mark_safe

import requests

from sentry.constants import LOG_LEVELS
from sentry.plugins.bases.notify import NotifyPlugin
from sentry.web.helpers import render_to_string

import sentry_flowdock


class FlowdockOptionsForm(forms.Form):
    token = forms.CharField(
        help_text='Your flow API token.')
    from_address = forms.EmailField(
        help_text="Default From email address",
        initial=settings.DEFAULT_FROM_EMAIL,
    )
    minimum_alert_level = forms.ChoiceField(
        help_text="Minimum Level needed to notify Flowdock",
        choices=[("{0}".format(k), "{0}".format(v.capitalize())) for k, v in LOG_LEVELS.items()],
        initial="40"
    )
    push_tags = forms.CharField(
        help_text='Tag keys to push as tags to Flowdock (version,level,hash)',
        initial="level,version",
        required=False)


ALPHANUMERIC_UNDERSCORES_WHITESPACE = r'^[a-z0-9_ ]+$'

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

    def is_configured(self, project, **kwargs):
        params = self.get_option
        return (params('token', project) and
                params('from_address', project) and
                params('minimum_alert_level', project) and
                params('push_tags', project))

    def _get_flow_tags(self, group, event, push_tags, fail_silently=False):
        """Simply pull the tags the user wants into a list

          If the user wants the tag 'level' then give them the value of what level is
        """
        try:
            push_tags = push_tags.split(",")
        except Exception as e:
            self.logger.exception('Issue with tags: {err}'.format(err=e))
            push_tags = []
            if not fail_silently:
                raise

        flow_tags = [] if 'level' not in push_tags else [group.get_level_display()]
        for tag in push_tags:
            if tag != "level":
                try:
                    flow_tags.append(dict(event.get_tags()).get(tag))
                except Exception as e:
                    self.logger.exception('Unexpected response from Flowdock: {err}'.format(err=e))
                    if not fail_silently:
                        raise
        return flow_tags

    def on_alert(self, alert, **kwargs):
        project = alert.project
        token = self.get_option('token', project)
        from_address = self.get_option('from_address', project)

        subject = '[{0}] ALERT: {1}'.format(
            project.name.encode('utf-8'),
            alert.message.encode('utf-8')[:50],
        )

        message = render_to_string('sentry_flowdock/alert.html', {
            'alert': alert,
        })

        self.send_payload(
            source=kwargs.get('source', 'Sentry'),
            from_address=from_address,
            subject=subject,
            content=message,
            from_name=kwargs.get('from_name', "Sentry"),
            link=alert.get_absolute_url(),
            token=token,
            **kwargs
        )

    def notify_users(self, group, event, fail_silently=False, **kwargs):
        project = group.project
        token = self.get_option('token', project)
        from_address = self.get_option('from_address', project)
        push_tags = self.get_option('push_tags', project)
        minimum_alert_level = self.get_option('minimum_alert_level', project)

        if int(minimum_alert_level) > int(group.level):
            return

        subject = '%s: %s' % (
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

        flow_tags = self._get_flow_tags(group, event, push_tags, fail_silently)

        self.send_payload(
            source=kwargs.get('source', 'Sentry'),
            from_address=from_address,
            subject=subject,
            content=message,
            from_name=kwargs.get('from_name', "Sentry"),
            tags=flow_tags,
            link=group.get_absolute_url(),
            project=project.name,
            token=token,
            fail_silently=fail_silently,
            **kwargs
        )

    def send_payload(self, source, from_address, subject, content, project=None,
                     from_name=None, tags=None, link=None, token=None,
                     format="html", encoding="utf-8", fail_silently=False, **kwargs):
        """This will send the message off to flowdock"""

        assert len(content) <= 8096, \
            'The `content` argument length must be 8096 characters or less. You are {}'.format(
                len(content))

        assert re.match(ALPHANUMERIC_UNDERSCORES_WHITESPACE, source, re.IGNORECASE), \
            'The `source` argument must contain only alphanumeric ' \
            'characters, underscores and whitespace.'

        try:
            validate_email(from_address)
        except ValidationError:
            raise ValidationError("'{addr}' is not a valid email address".format(addr=from_address))

        data = {'source': source.encode(encoding), 'from_address': from_address.encode(encoding),
                'subject': subject.encode(encoding), 'content': content.encode(encoding)}

        if project:
            assert re.match(ALPHANUMERIC_UNDERSCORES_WHITESPACE, project, re.IGNORECASE), \
                'The `project` argument must contain only alphanumeric ' \
                'characters, underscores and whitespace.'
            data['project'] = project.encode(encoding)

        if tags:
            assert isinstance(tags, (list, tuple)), "The `tags` must be a list"
            data['tags'] = ",".join(["#{tag}".format(tag=x) for x in tags]).encode(encoding)

        for item, label in [(from_name, "from_name"), (link, "link"), (format, "format")]:
            if item and len(item):
                data[label] = item

        encoded_data = urllib.urlencode(data)

        url = "https://api.flowdock.com/v1/messages/team_inbox/{token}".format(token=token)
        response = requests.post(url, data=encoded_data)
        data = json.loads(response.text)
        if response.status_code == 200:
            self.logger.info("[{code}] {text}".format(text=data, code=response.status_code))
            return True

        self.logger.error('Unexpected response from Flowdock: %s', data)
        if not fail_silently:
            raise requests.HTTPError("{err}".format(err=data))
