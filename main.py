from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import ssl, socket

app = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def form(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "result": None})

@app.post("/", response_class=HTMLResponse)
async def scan(request: Request, domain: str = Form(...)):
    result = get_ssl_info(domain)
    return templates.TemplateResponse("index.html", {"request": request, "result": result})

def get_ssl_info(domain):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(), server_hostname=domain)
    try:
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        issuer = dict(x[0] for x in cert['issuer'])
        issued_to = dict(x[0] for x in cert['subject'])

        result = {
            "Issued To": issued_to.get("commonName", "N/A"),
            "Issued By": issuer.get("commonName", "N/A"),
            "Valid From": cert.get("notBefore", "N/A"),
            "Valid To": cert.get("notAfter", "N/A"),
            "Serial Number": cert.get("serialNumber", "N/A")
        }
        return result
    except Exception as e:
        return {"error": str(e)}
