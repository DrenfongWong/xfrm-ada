with Ada.Text_IO;
with Ada.Streams;

with System.Storage_Elements;

with Interfaces.C;
with Interfaces.C.Extensions;

with Anet.Constants;

with xfrm_h;

with Xfrm.Thin;
with Xfrm.Sockets;

procedure Add_Sa
is
   Enc_Key : constant Anet.Byte_Array (1 .. 32) := (others => 10);
   Int_Key : constant Anet.Byte_Array (1 .. 64) := (others => 11);

   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin
   Sock.Init;
   Sock.Add_State
     (Src     => (192, 168, 1, 1),
      Dst     => (192, 168, 2, 1),
      Reqid   => 1,
      Spi     => 123,
      Enc_Key => Enc_Key,
      Enc_Alg => "aes",
      Int_Key => Int_Key,
      Int_Alg => "hmac(sha512)");
   Ada.Text_IO.Put_Line ("OK");
end Add_Sa;
