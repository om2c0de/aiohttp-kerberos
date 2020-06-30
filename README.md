# aiohttp-kerberos

Usage:
```
from aiohttp import web
from auth import init_kerberos, login_required


@login_required
async def handle(_):
    text = "Hello world!"
    return web.Response(text=text)


app = web.Application()
app.add_routes([web.get('/', handle)])


if __name__ == '__main__':
    init_kerberos()
    web.run_app(app, port=9099)
```
