INSERT INTO users (username,[password],email,firstname,lastname)
VALUES ('caryroys',CONVERT(varchar(50),hashbytes('sha1',cast('Testing123' as varchar(18))),2),'caroys@microsoft.com','Cary','Roys');
INSERT INTO users (username,[password],firstname,lastname)
VALUES ('billgates',CONVERT(varchar(50),hashbytes('sha1',cast('Need>640k' as varchar(18))),2),'Bill','Gates');
INSERT INTO users (username,[password],firstname,lastname)
VALUES ('jiminycricket',CONVERT(varchar(50),hashbytes('sha1',cast('RealWoodenBoy' as varchar(18))),2),'Jiminy','Cricket');