
# AUDIT = config.ui.audit
# AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')

# # noinspection PyBroadException
# @socketio.on('submission')
# def submission_on(data):
#     info = get_user_info(request, session)
#
#     if info.get('uname', None) is None:
#         return
#
#     LOGGER.info("[%s@%s] SocketIO:Submission - Event received => %s" % (info.get('uname', None), info['ip'], data))
#     if AUDIT:
#         AUDIT_LOG.info("%s [%s] :: %s(start)" % (info.get('uname', None),
#                                                  info.get('classification', classification.UNRESTRICTED),
#                                                  "socketsrv_submission_on"))
#     emit('connected', data)
#
#     q = CommsQueue('traffic', private=True)
#     try:
#         for msg in q.listen():
#             if msg['type'] == "message":
#                 body = json.loads(msg['data'])
#                 submission_classification = body.get('body', {}).get('classification', classification.UNRESTRICTED)
#                 message = {
#                     'body': body,
#                     'mtype': 'SubmissionIngested',
#                     'reply_to': None,
#                     'sender': u'middleman',
#                     'succeeded': True,
#                     'to': u'*'
#                 }
#
#                 if classification.is_accessible(info.get('classification', classification.UNRESTRICTED),
#                                                 submission_classification):
#                     emit('SubmissionIngested', message)
#     except Exception:
#         LOGGER.exception("[%s@%s] SocketIO:Submission" % (info.get('uname', None), info['ip']))
#     finally:
#         LOGGER.info("[%s@%s] SocketIO:Submission - Connection to client was terminated" %
#                     (info.get('uname', None), info['ip']))
#         if AUDIT:
#             AUDIT_LOG.info("%s [%s] :: %s(stop)" % (info.get('uname', None),
#                                                     info.get('classification', classification.UNRESTRICTED),
#                                                     "socketsrv_submission_on"))
