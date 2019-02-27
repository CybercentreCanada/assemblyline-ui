# AUDIT = config.ui.audit
# AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')

# # noinspection PyBroadException
# @socketio.on('alert')
# def alert_on(data):
#     info = get_user_info(request, session)
#
#     if info.get('uname', None) is None:
#         return
#
#     LOGGER.info("[%s@%s] SocketIO:Alert - Event received => %s" % (info.get('uname', None), info['ip'], data))
#     if AUDIT:
#         AUDIT_LOG.info("%s [%s] :: %s(start)" % (info.get('uname', None),
#                                                  info.get('classification', classification.UNRESTRICTED),
#                                                  "socketsrv_alert_on"))
#     emit('connected', data)
#
#     q = CommsQueue('alerts', private=True)
#     try:
#         for msg in q.listen():
#             if msg['type'] == "message":
#                 data = json.loads(msg['data'])
#                 if classification.is_accessible(info.get('classification', classification.UNRESTRICTED),
#                                                 data.get('body', {}).get('classification',
#                                                                          classification.UNRESTRICTED)):
#                     emit('AlertCreated', data)
#     except Exception:
#         LOGGER.exception("[%s@%s] SocketIO:Alert" % (info.get('uname', None), info['ip']))
#     finally:
#         LOGGER.info("[%s@%s] SocketIO:Alert - Connection to client was terminated" %
#                     (info.get('uname', None), info['ip']))
#         if AUDIT:
#             AUDIT_LOG.info("%s [%s] :: %s(stop)" % (info.get('uname', None),
#                                                     info.get('classification', classification.UNRESTRICTED),
#                                                     "socketsrv_alert_on"))
#
#