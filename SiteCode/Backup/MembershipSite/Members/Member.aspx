<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Member.aspx.cs" Inherits="MembershipSite.Members.Member" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
    <div>
        <h2>Membership Page</h2>
        <asp:Label ID="Label1" runat="server" Text="Welcome "></asp:Label>
        <asp:LoginName ID="LoginName" runat="server" />
        (<asp:LoginStatus ID="LoginStatus" runat="server" LogoutAction="Redirect" LogoutPageUrl="~/default.aspx" />)
    </div>
    </form>
</body>
</html>
