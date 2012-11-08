--
--  Copyright (C) 2012 secunet Security Networks AG
--  Copyright (C) 2012 Reto Buerki <reet@codelabs.ch>
--
--  This program is free software; you can redistribute it and/or modify it
--  under the terms of the GNU General Public License as published by the
--  Free Software Foundation; either version 2 of the License, or (at your
--  option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
--
--  This program is distributed in the hope that it will be useful, but
--  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
--  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
--  for more details.
--
--  As a special exception, if other files instantiate generics from this
--  unit,  or  you  link  this  unit  with  other  files  to  produce  an
--  executable   this  unit  does  not  by  itself  cause  the  resulting
--  executable to  be  covered by the  GNU General  Public License.  This
--  exception does  not  however  invalidate  any  other reasons why  the
--  executable file might be covered by the GNU Public License.
--

with Ada.Text_IO;

with Anet;

with Xfrm.Sockets;

procedure Add_Sa
is
   Enc_Key : constant Anet.Byte_Array (1 .. 32) := (others => 10);
   Int_Key : constant Anet.Byte_Array (1 .. 64) := (others => 11);

   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin
   Sock.Init;
   Sock.Add_State
     (Src           => (192, 168, 1, 1),
      Dst           => (192, 168, 2, 1),
      Reqid         => 1,
      Spi           => 123,
      Enc_Key       => Enc_Key,
      Enc_Alg       => "aes",
      Int_Key       => Int_Key,
      Int_Alg       => "hmac(sha512)",
      Lifetime_Soft => 30,
      Lifetime_Hard => 60);
   Ada.Text_IO.Put_Line ("OK");
end Add_Sa;
