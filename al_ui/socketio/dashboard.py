# # noinspection PyBroadException
# @socketio.on('monitor')
# def monitoring_on(data):
#     info = get_user_info(request, session)
#
#     if info.get('uname', None) is None:
#         return
#
#     LOGGER.info("[%s@%s] SocketIO:Monitor - Event received => %s" % (info.get('uname', None), info['ip'], data))
#     emit('connected', data)
#
#     q = CommsQueue('status', private=True)
#     try:
#         for msg in q.listen():
#             if msg['type'] == "message":
#                 data = json.loads(msg['data'])
#                 emit(data['mtype'], data)
#     except Exception:
#         LOGGER.exception("[%s@%s] SocketIO:Monitor" % (info.get('uname', None), info['ip']))
#     finally:
#         LOGGER.info("[%s@%s] SocketIO:Monitor - Connection to client was terminated" % (info.get('uname', None),
#                                                                                         info['ip']))
#