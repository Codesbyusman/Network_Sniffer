from webob.dec import wsgify
from paste import httpserver
from paste.proxy import TransparentProxy


def print_trip(request, response):
    """
    just prints the request and response
    """
    print("Request\n==========\n\n")
    print (str(request))
    print ("\n\n")
    print ("Response\n==========\n\n")
    print (str(response))
    print ("\n\n")


class HTTPMiddleware(object):
    """
    serializes every request and response
    """

    def __init__(self, app, record_func=print_trip):
        self._app = app
        self._record = record_func

    @wsgify
    def __call__(self, req):
        result = req.get_response(self._app)
        try:
            self._record(req.copy(), result.copy())
        except Exception as ex: #return response at all costs
            print (ex)
        return result

httpserver.serve(HTTPMiddleware(TransparentProxy()), "0.0.0.0", port=8088)

class FileIntercept(object):
    """
    wsgi: middleware
    given request.path will call wsgi app matching that path instead
    of dispatching to the wrapped application
    """
    def __init__(self, app, file_intercept={}):
        self._app = app
        self._f = file_intercept

    def __call__(self, environ, start_response):
        request = Request(environ)
        if request.path.lower() in self._f:
            response = request.get_response(self._f[request.path.lower()])
        else:
            response = request.get_response(self._app)
        return response(environ, start_response)

    app = FileIntercept(TransparentProxy(),
                             file_intercept={"/js/config.js":Response("/*new settings*/")})
    httpserver.serve(HTTPMiddleware(app), "0.0.0.0", port=8088)