<%@ taglib uri="http://rhn.redhat.com/rhn" prefix="rhn" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://struts.apache.org/tags-html" prefix="html" %>
<%@ taglib uri="http://struts.apache.org/tags-bean" prefix="bean" %>
<%@ taglib uri="http://rhn.redhat.com/tags/list" prefix="rl" %>


<html>
<head>
</head>
<body>
<rhn:toolbar base="h1" icon="header-system" imgAlt="system.common.systemAlt"
 helpUrl="/rhn/help/user/en-US/s2-sm-system-list.jsp#s3-sm-system-list-inact">
  <bean:message key="inactivelist.jsp.header"/>
</rhn:toolbar>
<c:set var="showLastCheckinSort" value="true"/>

<rl:listset name="systemListSet" legend="system">
    <rhn:csrf />
    <rhn:submitted />
    <%@ include file="/WEB-INF/pages/common/fragments/systems/system_listdisplay.jspf" %>
</rl:listset>

</body>
</html>
