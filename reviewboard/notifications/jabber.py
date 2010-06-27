import logging

from pyxmpp.streamtls import TLSSettings
from pyxmpp.jabber.client import JabberClient
from pyxmpp.message import Message
from pyxmpp.jid import JID


from django.contrib.sites.models import Site
from djblets.siteconfig.models import SiteConfiguration

from reviewboard.reviews.models import ReviewRequest, Review
from reviewboard.reviews.signals import review_request_published, \
                                        review_published, reply_published

from reviewboard.notifications import email
def get_jid_for_user(user):
    return user.email

def get_jids_for_group(group):
    if group.mailing_list:
        if group.mailing_list.find(",") == -1:
            # The mailing list field has only one e-mail address in it,
            # so we can just use that and the group's display name.
            return [ group.mailing_list ] 
        else:
            # The mailing list field has multiple e-mail addresses in it.
            # We don't know which one should have the group's display name
            # attached to it, so just return their custom list as-is.
            return [ g.strip() for g in group.mailing_list.split(',') ]
    else:
        return [get_jid_for_user(u)
                for u in g.users.filter(is_active=True)]



def send_jabber_messages(jid,password,to_jids,message="",subject="", server=None,port=None, tls_enabled=False, tls_force=False, auth_methods = ['sasl:PLAIN', 'sasl:DIGEST-MD5']):
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
            for to_jid in to_jids:
                logging.debug("Sending jabber message to %s"%to_jid)
                try:
                    send_msg(self.get_stream(), JID(to_jid), self.jid, subject, message )
                except Exception, e:
                    logging.error("Failed sending message to %s (%s)"%to_jid, str(e))
            self.disconnect()


    if tls_enabled:
      tls_settings = TLSSettings(verify_peer = False, require=True)
    else:
      tls_settings = None
    
    logging.debug("Connecting with jabber id %s"%jid)
    c=Client(JID(jid),password,server=server,port=port,tls_settings=tls_settings, auth_methods = auth_methods)
    c.connect()
    c.loop(1)


def connect_signals():
    review_request_published.connect(review_request_published_cb,
                                     sender=ReviewRequest)
    review_published.connect(review_published_cb, sender=Review)
    reply_published.connect(reply_published_cb, sender=Review)


def send_review_message(user, review_request, extra_recipients, subject, message):
    siteconfig = SiteConfiguration.objects.get_current()
    # current_site = Site.objects.get_current()
    # domain_method = siteconfig.get("site_domain_method")
    # base_url = '%s://%s' % (domain_method, current_site.domain)
    # review_origin = get_jid_for_user(user)
    # review_url = base_url + review_request.get_absolute_url()

    # get recipients
    from_email = get_jid_for_user(user)

    recipients = set([from_email])
    to_field = set()

    if review_request.submitter.is_active:
        recipients.add(get_jid_for_user(review_request.submitter))

    for u in review_request.target_people.filter(is_active=True):
        recipients.add(get_jid_for_user(u))
        to_field.add(get_jid_for_user(u))

    for group in review_request.target_groups.all():
        for address in get_jids_for_group(group):
            recipients.add(address)

    for profile in review_request.starred_by.all():
        if profile.user.is_active:
            recipients.add(get_jid_for_user(profile.user))

    #extra_recipients = email.harvest_people_from_review_request(review_request)
    if extra_recipients:
        for recipient in extra_recipients:
            if recipient.is_active:
                recipients.add(get_jid_for_user(recipient))

    try:
        send_jabber_messages( siteconfig.get("jabber_id") + "/" + siteconfig.get("jabber_resource"),
                             siteconfig.get("jabber_password"),
                             recipients,
                             subject = subject,
                             message = message,
                             tls_enabled = siteconfig.get("jabber_use_tls"),
                             tls_force = siteconfig.get("jabber_force_tls"))

    except Exception, e:
        logging.error("Failed sending review messages from %s to %s (%s)"%(siteconfig.get("jabber_id"), str(recipients), str(e)))


def review_request_published_cb(sender, user, review_request, changedesc,
                                **kwargs):
    """
    Listens to the ``review_request_published`` signal and sends an
    email if this type of notification is enabled (through
    ``mail_send_review_mail`` site configuration).
    """
    siteconfig = SiteConfiguration.objects.get_current()

    if siteconfig.get("jabber_send_review"):
        send_review(user, review_request, changedesc)

def review_published_cb(sender, user, review, **kwargs):
    """
    Listens to the ``review_published`` signal and sends an email if
    this type of notification is enabled (through
    ``mail_send_review_mail`` site configuration).
    """
    siteconfig = SiteConfiguration.objects.get_current()
    if siteconfig.get("jabber_send_review"):
        send_review_published(user, review)

def reply_published_cb(sender, user, reply, **kwargs):
    """
    Listens to the ``reply_published`` signal and sends an email if
    this type of notification is enabled (through
    ``mail_send_review_mail`` site configuration).
    """
    siteconfig = SiteConfiguration.objects.get_current()
    if siteconfig.get("jabber_send_review"):
        send_review_reply(user, reply)

def get_url_for_review(review):
  current_site = Site.objects.get_current()
  siteconfig = SiteConfiguration.objects.get_current()
  domain_method = siteconfig.get("site_domain_method")
  url = '%s://%s%s'%(domain_method, current_site, review.get_absolute_url())
  return url

def send_review(user, review_request, changedesc):
    # If the review request is not yet public or has been discarded, don't send
    # any mail.
    if not review_request.public or review_request.status == 'D':
        return
    
    subject = "Review Request: \"%s\""%review_request.summary
    if review_request.email_message_id:
        # Fancy quoted "replies"
        subject = "Re: " + subject
        reply_message_id = review_request.email_message_id
        extra_recipients = email.harvest_people_from_review_request(review_request)
    else:
        extra_recipients = None

    message_body = "%s by %s at %s"%(subject, review_request.submitter.username, get_url_for_review(review_request))
    send_review_message(user, review_request, extra_recipients, subject, message_body)
        

def send_review_published(user, review):
    review_request = review.review_request

    if not review_request.public:
        return
    
    if not review.ship_it:
      subject = "Reviwed \"%s\""%(review_request.summary)
    else:
      subject = "Reviewed \"%s\", Ship it!"%(review_request.summary)

    message_body = "%s by %s at %s"%(subject, review.user, get_url_for_review(review_request))
    send_review_message(user, review_request, None, subject, message_body)

def send_review_reply(user, reply):
    
    review = reply.base_reply_to
    review_request = review.review_request
    
    if not review_request.public:
        return

    subject = "Reply To: \"%s\""%review_request.summary
    message_body = "%s by %s at %s"%(subject, reply.user.username, get_url_for_review(review_request))
    send_review_message(user, review_request, email.harvest_people_from_review_request(review_request), subject, message_body)


    

