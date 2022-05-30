USE [master]
GO

--The *.mdf and *.ldf file paths will change according to your version of SQL Server

/****** Object:  Database [MyWebApp]    Script Date: 3/30/2022 3:25:12 PM ******/
CREATE DATABASE [MyWebApp]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'MyWebApp', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\MyWebApp.mdf' , SIZE = 8192KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
 LOG ON 
( NAME = N'MyWebApp_log', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\MyWebApp_log.ldf' , SIZE = 8192KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
 WITH CATALOG_COLLATION = DATABASE_DEFAULT
GO

IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [MyWebApp].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO

ALTER DATABASE [MyWebApp] SET ANSI_NULL_DEFAULT OFF 
GO

ALTER DATABASE [MyWebApp] SET ANSI_NULLS OFF 
GO

ALTER DATABASE [MyWebApp] SET ANSI_PADDING OFF 
GO

ALTER DATABASE [MyWebApp] SET ANSI_WARNINGS OFF 
GO

ALTER DATABASE [MyWebApp] SET ARITHABORT OFF 
GO

ALTER DATABASE [MyWebApp] SET AUTO_CLOSE OFF 
GO

ALTER DATABASE [MyWebApp] SET AUTO_SHRINK OFF 
GO

ALTER DATABASE [MyWebApp] SET AUTO_UPDATE_STATISTICS ON 
GO

ALTER DATABASE [MyWebApp] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO

ALTER DATABASE [MyWebApp] SET CURSOR_DEFAULT  GLOBAL 
GO

ALTER DATABASE [MyWebApp] SET CONCAT_NULL_YIELDS_NULL OFF 
GO

ALTER DATABASE [MyWebApp] SET NUMERIC_ROUNDABORT OFF 
GO

ALTER DATABASE [MyWebApp] SET QUOTED_IDENTIFIER OFF 
GO

ALTER DATABASE [MyWebApp] SET RECURSIVE_TRIGGERS OFF 
GO

ALTER DATABASE [MyWebApp] SET  DISABLE_BROKER 
GO

ALTER DATABASE [MyWebApp] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO

ALTER DATABASE [MyWebApp] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO

ALTER DATABASE [MyWebApp] SET TRUSTWORTHY OFF 
GO

ALTER DATABASE [MyWebApp] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO

ALTER DATABASE [MyWebApp] SET PARAMETERIZATION SIMPLE 
GO

ALTER DATABASE [MyWebApp] SET READ_COMMITTED_SNAPSHOT OFF 
GO

ALTER DATABASE [MyWebApp] SET HONOR_BROKER_PRIORITY OFF 
GO

ALTER DATABASE [MyWebApp] SET RECOVERY SIMPLE 
GO

ALTER DATABASE [MyWebApp] SET  MULTI_USER 
GO

ALTER DATABASE [MyWebApp] SET PAGE_VERIFY CHECKSUM  
GO

ALTER DATABASE [MyWebApp] SET DB_CHAINING OFF 
GO

ALTER DATABASE [MyWebApp] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO

ALTER DATABASE [MyWebApp] SET TARGET_RECOVERY_TIME = 60 SECONDS 
GO

ALTER DATABASE [MyWebApp] SET DELAYED_DURABILITY = DISABLED 
GO

ALTER DATABASE [MyWebApp] SET ACCELERATED_DATABASE_RECOVERY = OFF  
GO

ALTER DATABASE [MyWebApp] SET QUERY_STORE = OFF
GO

ALTER DATABASE [MyWebApp] SET  READ_WRITE 
GO


USE [MyWebApp]
GO

/****** Object:  Table [dbo].[users]    Script Date: 3/30/2022 3:28:27 PM ******/
SET ANSI_NULLS ON
GO

SET QUOTED_IDENTIFIER ON
GO

CREATE TABLE [dbo].[users](
	[username] [nchar](50) NOT NULL,
	[password] [nchar](50) NOT NULL,
	[email] [nchar](50) NULL,
	[firstname] [nchar](50) NULL,
	[lastname] [nchar](10) NULL,
 CONSTRAINT [PK_users] PRIMARY KEY CLUSTERED 
(
	[username] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO