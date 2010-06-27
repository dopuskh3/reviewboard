from datetime import datetime
import logging

from pyxmpp.streamtls import TLSSettings
from pyxmpp.jabber.client import JabberClient
from pyxmpp.message import Message
from pyxmpp.jid import JID


from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from djblets.siteconfig.models import SiteConfiguration

from reviewboard.reviews.models import ReviewRequest, Review
from reviewboard.reviews.signals import review_request_published, \
                                        review_published, reply_published
from reviewboard.reviews.views import build_diff_comment_fragments

from reviewboard.notifications import email

def send_jabber_message(jid,password,to_jid,message="",subject="", server=None,port=None, tls_enabled=False, tls_force=False, auth_methods = ['sasl:PLAIN', 'sasl:DIGEST-MD5']):
    """Connect as client to a Jabber/XMPP server and call the provided
    function when stream is ready for IM. The function will be called
    with one argument -- the XMPP stream. After function returns the stream is
    closed."""
    def send_msg(stream, msg_to, msg_from, msg_subject, msg_body):
        m = Message(to_jid = msg_to,
                          from_jid=msg_from,
                          subject = msg_subject,
                          body = msg_body)
        m.set_type('chat')
        stream.send(m)

    class Client(JabberClient):
        """The simplest client implementation."""
        def session_started(self):
            """Call the function provided when the session starts and exit."""
            send_msg(self.get_stream(), JID(to_jid), self.jid, subject, message )
            self.disconnect()


    if tls_enabled:
      tls_settings = TLSSettings(verify_peer = False, require=True)
    else:
      tls_settings = None

    c=Client(JID(jid),password,server=server,port=port,tls_settings=tls_settings, auth_methods = auth_methods)
    c.connect()
    c.loop(1)


def connect_signals():
    review_request_published.connect(review_request_published_cb,
                                     sender=ReviewRequest)
    review_published.connect(review_published_cb, sender=Review)
    reply_published.connect(reply_published_cb, sender=Review)



def review_request_published_cb(sender, user, review_request, changedesc,
                                **kwargs):
    """
    Listens to the ``review_request_published`` signal and sends an
    email if this type of notification is enabled (through
    ``mail_send_review_mail`` site configuration).
    """
    siteconfig = SiteConfiguration.objects.get_current()

    if siteconfig.get("jabber_send_review"):

        current_site = Site.objects.get_current()
        domain_method = siteconfig.get("site_domain_method")
        base_url = '%s://%s' % (domain_method, current_site.domain)
        review_origin = email.get_email_address_for_user(user)
        review_url = base_url + review_request.get_absolute_url()

        # get recipients
        from_email = email.get_email_address_for_user(user)

        recipients = set([from_email])
        to_field = set()

        if review_request.submitter.is_active:
            recipients.add(email.get_email_address_for_user(review_request.submitter))

        for u in review_request.target_people.filter(is_active=True):
            recipients.add(email.get_email_address_for_user(u))
            to_field.add(email.get_email_address_for_user(u))

        for group in review_request.target_groups.all():
            for address in email.get_email_addresses_for_group(group):
                recipients.add(address)

        for profile in review_request.starred_by.all():
            if profile.user.is_active:
                recipients.add(email.get_email_address_for_user(profile.user))

        extra_recipients = email.harvest_people_from_review_request(review_request)
        if extra_recipients:
            for recipient in extra_recipients:
                if recipient.is_active:
                    recipients.add(email.get_email_address_for_user(recipient))


        print "SENDING REVIEW TO " + str(recipients)
        review_message = """
New review request at : %s
"""%review_url
        for jabber_id in recipients:
            try:
                send_jabber_message( siteconfig.get("jabber_id") + "/" + siteconfig.get("jabber_resource"),
                                     siteconfig.get("jabber_password"),
                                     jabber_id,
                                     subject = "Review request",
                                     message = review_message,
                                     tls_enabled = siteconfig.get("jabber_use_tls"),
                                     tls_force = siteconfig.get("jabber_force_tls"))

            except Exception, e:
                print "CANNOT SEND JABBER REVIEW" + str(e)


def review_published_cb(sender, user, review, **kwargs):
    """
    Listens to the ``review_published`` signal and sends an email if
    this type of notification is enabled (through
    ``mail_send_review_mail`` site configuration).
    """
    siteconfig = SiteConfiguration.objects.get_current()
    if siteconfig.get("jabber_send_review"):
        print "Review published cb"


def reply_published_cb(sender, user, reply, **kwargs):
    """
    Listens to the ``reply_published`` signal and sends an email if
    this type of notification is enabled (through
    ``mail_send_review_mail`` site configuration).
    """
    siteconfig = SiteConfiguration.objects.get_current()
    if siteconfig.get("jabber_send_review"):
      print "Reply published"


