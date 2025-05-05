# Meta-package with all key symbols from FastHTML and Starlette. [cite: 6]
# Import it like this at the start of every FastHTML app. [cite: 6]

from fasthtml.common import *


# The FastHTML app object and shortcut to `app.route`
app,rt = fast_app()

# Enums constrain the values accepted for a route parameter
name = str_enum('names', 'Alice', 'Bev', 'Charlie')

# Passing a path to `rt` is optional. [cite: 8]
# If not passed (recommended), the function name is the route ('/foo') [cite: 8]
# Both GET and POST HTTP methods are handled by default
# Type-annotated params are passed as query params (recommended) unless a path param is defined (which it isn't here)
@app.get("/")
def foo():
    return Title("FastHTML"), H1("My web app") # Updated to use `nm` instead of `name`


serve()