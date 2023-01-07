# 概述

在登录泛微云桥之后，通过模拟恶意外部系统，可以实现RCE，且拿到的权限一般是管理员或system权限，可以看演示中whoami的返回。

# 影响版本

versions <= 最新(20221013)

# 原理

## 创建一个外部系统

首先，我们需要创建一个外部系统，该外部系统的url是我们的恶意服务器，外部系统的创建在weaver.weixin.outsys.controller.OutsysSysInfoController的add方法这里，访问地址是/main/outsys/add，我们需要重点关注：

```java
public void add() throws Exception {
    ...
    JSONObject json = TicketTools.checkECLogin2(accessUrl, account, password, this.getRequest());
    ...
    int flag = TicketTools.checkECProp2(accessUrl, sessionkey, sysinfoid);
    ...
}
```

在添加外部系统的时候该项目会去访问指定的外部系统进行验证，CheckECLogin2的主要代码如下：

```java
String url = accessurl + "/mobile/plugin/AdminVerifyLogin.jsp";
NameValuePair[] param = null;
param = new NameValuePair[]{new NameValuePair("loginid", loginid), new NameValuePair("password", password), new NameValuePair("ipaddress", ToolWeb.getIpAddr(request))};
String content = ToolHttp.doHttpPost(url, param, "GBK");
if (StringUtils.isNotEmpty(content)) {
    JSONObject jo = JSONObject.fromObject(content);
    if (jo.containsKey("message")) {
        msg = jo.getString("message");
    }

    if (jo.containsKey("sessionkey")) {
        sessionkey = jo.getString("sessionkey");
    }

    if ("1".equals(msg) && !"".equals(sessionkey)) {
        status = 0;
    }

    if (msg.equals("2")) {
        msg = "OA管理员密码输入错误,请确认输入的是泛微E-cology系统的管理员密码";
    } else if (msg.equals("3")) {
        msg = "验证OA账号密码失败:用户不存在";
    } else if (msg.equals("10")) {
        msg = "验证OA账号密码失败:不是系统管理员账号";
    } else if (msg.equals("11")) {
        msg = "验证OA账号密码失败:用户名,密码,ip为空";
    }
} else {
    msg = "请检查输入的OA系统访问地址在云桥服务器是否可以访问!";
}
```

即，我们创建的恶意服务器需要在被访问/mobile/plugin/AdminVerifyLogin.jsp的时候返回包含message和sessionkey的json字段。

checkECProp2的主要代码如下：

```java
String postdata = "operation=getprop";
String content = ToolHttp.doSimpleGet(accessurl + "/mobile/plugin/WxInterface.jsp?sessionkey=" + sessionkey, postdata);
if (StringUtils.isNotEmpty(content)) {
    JSONObject jo = JSONObject.fromObject(content);
    String message = "";
    if (jo.containsKey("message")) {
        message = jo.getString("message");
    }

    if ("1".equals(message)) {
        String _outsysid = Util.getJSONValue(jo, "outsysid");
        String _accesstoken = Util.getJSONValue(jo, "accesstoken");
        if (!"".equals(_outsysid) && !"".equals(_accesstoken)) {
            Record outsysinfo = SafeDb.findFirst("select id from wx_outsys_sysinfo where id=? and interface_password=? and id<> ? and (isdelete=0 or isdelete is null)" + ToolString.buildSqlInLimit(), new Object[]{_outsysid, _accesstoken, outsysid});
            if (outsysinfo != null) {
                return 4;
            }
        }

        String cVersion = Util.getJSONValue(jo, "cVersion");
        int ifLimitE9 = Util.getIntValue(ToolProp.getPropValue("version", "ifLimitE9"), 1);
        if (cVersion != null && cVersion.startsWith("9") && ifLimitE9 == 1) {
            return 6;
        }
    } else if ("3".equals(message)) {
        return 3;
    }
}
```

即，我们创建的恶意服务器需要在被访问/mobile/plugin/WxInterface.jsp的时候返回包含message、outsysid、accesstoken、cVersion的json字段。

在保证恶意服务器能够按照上述要求返回之后，即可向/main/outsys/add发送对应的post报文创建外部系统，返回报文是json格式，内容包含我们创建的外部系统的sysId。

## 创建一个应用

我们通过weaver.weixin.wework.controller.WeWorkAgentInfoController的save方法创建应用，其关键代码如下：

```java
public void save() throws Exception {
    ...
    try {
        WeWorkAgentInfoModel appInfo = (WeWorkAgentInfoModel)this.getModel(WeWorkAgentInfoModel.class, "appInfo");
        String operation = this.getPara("operation");
        int setmainurl = Util.getIntValue(this.getPara("setmainurl"));
        String menuid;
        String menutype;
        if (StrKit.notBlank(operation)) {
            appInfo.set("creatorid", this.getUserid());
            appInfo.set("createtime", new Date());
            String templateid = Util.null2String(this.getPara("templateid"));
            menuid = Util.null2String(this.getPara("templatetype"));
            TemplateInfo ti = TemplateManager.getTemplateInfo(templateid);
            if ("0".equals(menuid) && !License.checkModule(String.valueOf(ti.getModuleid()))) {
                templateid = "";
            }

            appInfo.set("templateid", templateid);
            WeWorkAgentInfoModel.dao.insert(appInfo);
            if (!"".equals(templateid)) {
                menutype = Util.null2String(this.getPara("outsysid"));
                TemplateManager.createAgentRelate(templateid, menuid, menutype, this.getTenantId(), appInfo.getStr("syscorpid"), appInfo.getStr("id"), this.getUserid());
            }
        } else {
            appInfo.set("updaterid", this.getUserid());
            appInfo.set("updatetime", new Date());
            WeWorkAgentInfoModel.dao.update(appInfo);
        }
    }
    ...
}
```

其中`WeWorkAgentInfoModel.dao.update(appInfo);`实现了创建应用，我们在后面需要用到创建的应用id，所以我们需要能控创建的应用id，审计`WeWorkAgentInfoModel appInfo = (WeWorkAgentInfoModel)this.getModel(WeWorkAgentInfoModel.class, "appInfo");`的getModel方法，它最终会调用到com.jfinal.core.ModelInjector的injectActiveRecordModel方法，该方法的关键代码如下：

```java
for (Entry<String, String[]> e : parasMap.entrySet()) {
    String paraKey = e.getKey();
    if (paraKey.startsWith(modelNameAndDot)) {
        String paraName = paraKey.substring(modelNameAndDot.length());
        Class colType = table.getColumnType(paraName);
        if (colType == null)
            throw new ActiveRecordException("The model attribute " + paraKey + " is not exists.");
        String[] paraValue = e.getValue();
        try {
            // Object value = Converter.convert(colType, paraValue != null ? paraValue[0] : null);
            Object value = paraValue[0] != null ? TypeConverter.convert(colType, paraValue[0]) : null;
            model.set(paraName, value);
        } catch (Exception ex) {
            if (skipConvertError == false)
                throw new RuntimeException("Can not convert parameter: " + modelNameAndDot + paraName, ex);
        }
    }
}
```

即，如果我们传入一个appInfo.id字段，这里会为appInfo设置id的值，从而达到我们可控appid的效果。

## 绑定应用

我们需要绑定应用，这一点通过weaver.weixin.app.shakearound.controller.WxShakeSignInController的index方法实现，其关键代码如下：

```java
public void index() {
    String sysAppId = this.getPara();
    int imType = this.getParaToInt("imtype", 0);
    String ticket = this.getPara("ticket");
    int singinType = this.getParaToInt("singinType", 0);
    String outSysId = this.getPara("outsysid");
    WxClientUser wcu = WxClientUserManager.getWxClientUserByRequest(this.getRequest(), true);
    wcu.setCurrentSysAppId(sysAppId);
    ...
}
```

即，我们只需要访问/wxclient/app/shake/sign/xxx，即可为绑定应用为id是xxx的应用，这里绑定应用为上文我们创建的应用。

## 绑定外部系统

我们还需要为当前用户绑定外部系统，这一点通过weaver.weixin.outsys.controller.OutsysSysInfoController的setOutsysInfoToUser方法，其关键代码如下：

```java
public void setOutsysInfoToUser() {
    try {
        WxClientUser wxcu = (WxClientUser)this.getSessionAttr("WXCLIENTUSER");
        if (wxcu == null) {
            this.renderJsonMsg("无法验证您的身份！", false);
            return;
        }

        String outsysid = this.getPara("outsysid");
        if (StrKit.isBlank(outsysid)) {
            this.renderJsonMsg("访问条件外部系统ID不能为空", false);
        } else {
            OutSysInfo outsys = WxClientUserManager.getOutSysByOutSysId(outsysid);
            wxcu.setLastAccessOutSys(outsys);
            this.renderJsonMsg("操作成功", true);
        }
    } catch (Exception var4) {
        logger.error(var4.getMessage(), var4);
        this.renderJsonMsg("程序异常，请联系管理员！", false);
    }

}
```

即我们只需要传入/wxclient/app/outsys/setOutsysInfoToUser?outsysid=xxx，即可根据外部系统的id，将外部系统绑定到该用户，后续会用到。

这里我们需要为当前用户绑定刚才创建的恶意服务器外部系统。

## 任意文件写

任意文件写借助weaver.weixin.api.controller.FileDownloadController的sendfile方法实现，其关键代码如下：

```java
public void sendFile() {
    try {
        WxClientUser wxcu = (WxClientUser)this.getSessionAttr("WXCLIENTUSER");
        if (wxcu == null) {
            this.renderJsonMsg("无法验证您的身份！", false);
            return;
        }

        String fileid = this.getPara("fileid");
        if (StrKit.isBlank(fileid)) {
            this.renderJsonMsg("文件ID不能为空！", false);
            return;
        }

        String sysagentid = wxcu.getCurrentSysAppId();
        String wxuserid = wxcu.getCurrentUserId();
        OutSysInfo outSys = wxcu.getLastAccessOutSys();
        if (outSys == null) {
            this.renderJsonMsg("找不到外部系统！", false);
            return;
        }

        WxCpConfigStorage wxCpConfigStorage = WxConfigDataProvider.getWxCpConfigStorageBySysAgentId(sysagentid);
        if (wxCpConfigStorage == null) {
            this.renderJsonMsg("找不到对应的应用！", false);
            return;
        }

        int cpType = wxCpConfigStorage.getCpType();
        OutSysUser ous = wxcu.getOutSysUserBySysId(outSys.getSysId());
        IOutSysFileDownload fd = outSys.getOutSysFileDownload();
        OutSysFileDownLoadResult rs = fd.downLoad(outSys, ous, fileid, "", this.getRequest(), this.getResponse());
        int errcode = rs.getErrcode();
        if (errcode == 0) {
            HttpFileInfo fileInfo = rs.getFileInfo();
            if (fileInfo == null) {
                this.renderJsonMsg("获取文件信息失败！", false);
                return;
            }

            if (StrKit.isBlank(fileInfo.getFileExt())) {
                this.renderJsonMsg("无法获取文件类型！", false);
                return;
            }

            byte[] content = fileInfo.getFileContent();
            File file = null;
            String filename = fileInfo.getFileName();
            String mediaId;
            if (StrKit.isBlank(filename)) {
                file = FileUtils.createTmpFile(new ByteArrayInputStream(content), UUID.randomUUID().toString(), fileInfo.getFileExt());
            } else {
                InputStream inputStream = new BufferedInputStream(new ByteArrayInputStream(content));
                BufferedOutputStream bos = null;

                try {
                    mediaId = FileUploadTools.getRandomFilePath();
                    File newFile = new File(mediaId);
                    if (!newFile.exists()) {
                        newFile.mkdirs();
                    }

                    file = new File(mediaId + File.separator + URLDecoder.decode(filename, outSys.getChartset()));
                    file.deleteOnExit();
                    bos = new BufferedOutputStream(new FileOutputStream(file));
                    int read = false;
                    byte[] bytes = new byte[102400];

                    int read;
                    while((read = inputStream.read(bytes)) != -1) {
                        bos.write(bytes, 0, read);
                    }

                    bos.flush();
                } 
    ...
}            
```

其中`String fileid = this.getPara("fileid");`要求我们访问的时候得加上fileid参数，例如`?fileid=1`，`OutSysInfo outSys = wxcu.getLastAccessOutSys();`会返回我们之前在“绑定外部系统”中绑定的外部系统，`WxCpConfigStorage wxCpConfigStorage = WxConfigDataProvider.getWxCpConfigStorageBySysAgentId(sysagentid);`会根据sysagentid返回应用，而sysagentid来自于`wxcu.getCurrentSysAppId();`，它会返回我们之前在“绑定应用”中绑定的应用id。

这里会执行到关键函数`fd.downLoad(outSys, ous, fileid, "", this.getRequest(), this.getResponse());`，这里的fd由外部系统而来，我们设置的外部系统是ecology，那么这里的fd就是EcologyFileDownload，它的downLoad函数的关键代码如下：

```java
public OutSysFileDownLoadResult downLoad(OutSysInfo outsys, OutSysUser outUser, String resource, String fileType, HttpServletRequest request, HttpServletResponse response) {
    ...
    if (content == null) {
        ...
        try {
            fileInfo = ToolHttp.fileDownload(downloadUrl, "", outsys.getHttpProxyBean());
            if (fileInfo != null && fileInfo.getFileContent() != null) {
                try {
                    remotehashcode = this.getHash(fileInfo.getFileContent(), "MD5");
                } catch (Exception var23) {
                }

                fileInfo.setFileHashCode(remotehashcode);
                fileInfo.setTimestamp(System.currentTimeMillis());
                if (disableCache == 0) {
                    this.putToCache(cacheKey, fileInfo);
                }
            }

            if (fileInfo.getFileContent() == FileDownloadRequestExecutor.download.fileSizeLimitedContent) {
                errcode = -20003;
            } else {
                errcode = 0;
            }
        } catch (WxRuntimeException var24) {
            errcode = var24.getRunTimeMsg().getErrorCode();
        }
    }

    ofrs.setFileInfo(fileInfo);
    ofrs.setErrcode(errcode);
    return ofrs;
}
```

这里`ToolHttp.fileDownload(downloadUrl, "", outsys.getHttpProxyBean())`的downloadUrl是我们创建外部系统时指定的url加上路径/mobile/plugin/Download.jsp以及一些其他参数，可以看到，这里会返回fileInfo，然后紧接着上面的weaver.weixin.api.controller.FileDownloadController的sendfile方法会将该文件保存，那么该文件路径和内容可控吗？

fileInfo来自于ToolHttp.fileDownload，该函数最终会执行到weaver.weixin.core.http.execute，其关键代码如下：

```java
public HttpFileInfo execute(CloseableHttpClient httpclient, HttpHost httpProxy, String uri, String queryParam) throws WxRuntimeException, ClientProtocolException, IOException {
    ...
    try {
        ...
        if (status == 200) {
            String contentType = method.getResponseHeader("Content-Type") == null ? "" : method.getResponseHeader("Content-Type").getValue();
            String contentDisposition = method.getResponseHeader("Content-Disposition") == null ? "" : method.getResponseHeader("Content-Disposition").getValue();
            InputStream is = method.getCustomResponseBodyAsStream();
            byte[] fileContent = null;
            boolean fileNameFromUrl;
            byte[] fileContent;
            if (is.available() > download.getFileLimitSize()) {
                fileContent = download.fileSizeLimitedContent;
            } else {
                ByteArrayOutputStream os = new ByteArrayOutputStream();
                fileNameFromUrl = false;
                byte[] b = new byte[1024];

                int len;
                while((len = is.read(b, 0, b.length)) != -1) {
                    os.write(b, 0, len);
                }

                fileContent = os.toByteArray();
                os.flush();
                os.close();
            }

            is.close();
            String fileName = "";
            if (StringUtils.isNotEmpty(contentDisposition)) {
                fileName = contentDisposition.substring(contentDisposition.indexOf("filename=") + 9);
                if (fileName.startsWith("\"") && fileName.endsWith("\"")) {
                    fileName = fileName.substring(1, fileName.length() - 1);
                }

                if (fileName.startsWith("'") && fileName.endsWith("'")) {
                    fileName = fileName.substring(1, fileName.length() - 1);
                }
            }
            ...
}
```

可以看到，文件下载请求的返回报文的Content-Disposition中的filename字段指明了文件名，即对于上面发送到我们的恶意服务器的url加上路径/mobile/plugin/Download.jsp以及一些其他参数的请求报文，只要我们在返回报文中加上`Content-Dispositio: filename=xxx`即可控制要写的文件名，这里可以直接加上`..`来路径穿越。

因此在后续weaver.weixin.api.controller.FileDownloadController的sendfile方法中，`file = new File(mediaId + File.separator + URLDecoder.decode(filename, outSys.getChartset()));`会按照我们的期望写入任意文件，且内容任意可控。

## RCE

上文实现了任意文件写漏洞，但是即使我们拥有写任意文件的能力依然无法getshell，因为ebridge对.jsp的访问限制得非常严格。

访问限制实现在weaver.weixin.outsys.api.OutSysProxyHandler的handle方法中，经过代码审计能够知道，在这里只有进入到`this.nextHandler.handle(target, request, response, isHandled);`，且isHandled为false才能成功触发.jsp执行。

我们看handle方法中的这一段关键代码：

```java
if (ifBcmap || !isNeedHandler || isLocalRequest && isLocalResource && !isNeedOutSysUser) {
    this.nextHandler.handle(target, request, response, isHandled);
}
```

可以发现，只要让isNeedHandler为false即可解析.jsp，isNeedhandler可以来源于：

```java
if (ifHxyh == 1 && request.getRequestURI().toLowerCase().indexOf("/mobile/plugin/2/pdfview/web/viewer.js") > -1) {
    isNeedHandler = false;
}
```

第二个条件很好满足，我们只需要创建一个/mobile/plugin/2/pdfview/web/viewer.jsp文件，即可让`request.getRequestURI().toLowerCase().indexOf("/mobile/plugin/2/pdfview/web/viewer.js") > -1`为true，那么ifHxyh是怎么来的呢？它的赋值语句是：

```java
int ifHxyh = Util.getIntValue(ToolProp.getPropValue("csdev_hxyh", "ifHxyh"), 0);
```

其中`ToolProp.getPropValue`最终会执行到weaver.weixin.core.tools.ToolProp的readProp方法，其代码如下：

```java
private static void readProp(String fileName) {
    BufferedInputStream is = null;

    try {
        File file = new File(Thread.currentThread().getContextClassLoader().getResource(fileName).toURI().getPath());
        if (!file.exists()) {
            throw new IllegalArgumentException("Properties file not found in classpath: " + fileName);
        }

        long ftime = file.lastModified();
        Long hftime = (Long)PORP_TIME.get(fileName);
        if (hftime == null || hftime != ftime) {
            Properties prop = new Properties();
            is = new BufferedInputStream(new FileInputStream(file));
            prop.load(is);
            PORP_OBJECT.put(fileName, prop);
            PORP_TIME.put(fileName, new Long(ftime));
        }
    } catch (Exception var15) {
    } finally {
        if (is != null) {
            try {
                is.close();
            } catch (IOException var14) {
            }
        }

    }

}
```

这里的filename是csdev_hxyh.properties，这里会读取该文件内容，并加载其中的属性，因此我们只需要借助前文实现的任意文件写，写csdev_hxyh.properties文件，内容是ifHxyh=1，即可让weaver.weixin.outsys.api.OutSysProxyHandler的handle方法中的ifHxyh为1。

之后我们只需要将shell写入到/mobile/plugin/2/pdfview/web/viewer.jsp，访问该路径即可执行该jsp文件。

# 演示

见本仓库的Demonstrate.mp4文件。

# EXP

见本仓库的server.py以及exp.py，使用方式是在目标能够访问到的机器上执行server.py，然后配置exp.py为目标的信息，执行exp.py，exp.py会打印出shell的访问路径。

演示中使用的exp就是这里的exp

# 免责声明

本仓库仅用于学习使用，请勿用于实际场景，一切后果由使用者自负。
