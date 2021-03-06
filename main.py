__author__ = 'radicalcakes'

#Execute this file for the main application

import tornado.ioloop
import tornado.web
import tornado.options
import tornado.escape
import tornado.httpserver
import tornado.tcpserver
import tornado.iostream

#custom tcphandler module
import TCPHandler


from tornado.options import define, options

define(name="port", default=7888, help="run on the given port", type=int)


class MainHandler(tornado.web.Application):
    def __init__(self):
        handlers = [
                (r"/", JsonParseHandler)
        ]
        tornado.web.Application.__init__(self, handlers)


class JsonParseHandler(tornado.web.RequestHandler):
    """
    Receives the message in a json format via a POST request
    """
    def post(self):
        print self.request.body
        dict_data = tornado.escape.json_decode(self.request.body)
        print dict_data
        packet = TCPHandler.Packet(dict_data)
        packet.send()


def main():
    print "Running the http server on the given port: " + str(options.port)
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(MainHandler())
    http_server.listen(options.port)
    io_loop = tornado.ioloop.IOLoop.instance()
    io_loop.start()


if __name__ == "__main__":
    main()