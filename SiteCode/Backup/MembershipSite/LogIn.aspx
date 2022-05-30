<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="LogIn.aspx.cs" Inherits="MembershipSite.LogInPage" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml" >
<head runat="server">
    <title></title>
</head>
<body>
    <form id="form1" runat="server">
    <div>
        <h2>LogIn Page</h2>
        <asp:Label ID="Label1" runat="server" Text="Please log in below to access the membership area."></asp:Label>
        <br />
        <br />
        <asp:Login ID="LoginControl" runat="server" 
            onauthenticate="LoginControl_Authenticate">
        </asp:Login>
    </div>
    </form>
</body>
</html>
