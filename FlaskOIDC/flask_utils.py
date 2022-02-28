from flask import Response, abort

from time import time

now = lambda: int(time())

def response_nocache(status=200, body=''):
    
    response = Response(status=status, response=body)
    
    # MDN recommended for various browsers
    response.headers.add_header('Cache-Control', 'no-cache')
    response.headers.add_header('Cache-Control', 'must-revalidate')
    response.headers.add_header('Pragma', 'no-cache')
    response.headers.add_header('Expires', 'Sun, 25 Jul 2021 15:42:14 GMT')
    return response


UnauthorizedError = lambda body=None: abort(status=401)

BadRequestError = lambda body=None: abort(status=400)

AppError = lambda body=None: abort(status=400)

ConflictError = lambda body=None: abort(status=400)

ForbiddenError = lambda body=None: abort(status=403)

