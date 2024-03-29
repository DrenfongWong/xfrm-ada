--
--  Copyright (C) 2012-2013 secunet Security Networks AG
--  Copyright (C) 2012-2013 Reto Buerki <reet@codelabs.ch>
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

with Xfrm.Sockets;

procedure Add_Policy
is
   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin
   Sock.Init;

   --  Transport mode

   Sock.Add_Policy
     (Mode           => Xfrm.Sockets.Mode_Transport,
      Sel_Src        => (192, 168, 1, 1),
      Sel_Src_Prefix => 32,
      Sel_Dst        => (192, 168, 2, 1),
      Sel_Dst_Prefix => 32,
      Tmpl_Src       => (0, 0, 0, 0),
      Tmpl_Dst       => (0, 0, 0, 0),
      Reqid          => 1,
      Direction      => Xfrm.Sockets.Direction_Out);

   --  Tunnel mode

   Sock.Add_Policy
     (Mode           => Xfrm.Sockets.Mode_Tunnel,
      Sel_Src        => (10, 1, 0, 0),
      Sel_Src_Prefix => 16,
      Sel_Dst        => (10, 2, 0, 0),
      Sel_Dst_Prefix => 16,
      Tmpl_Src       => (192, 168, 0, 1),
      Tmpl_Dst       => (192, 168, 0, 2),
      Reqid          => 2,
      Direction      => Xfrm.Sockets.Direction_In);
   Ada.Text_IO.Put_Line ("OK");
end Add_Policy;
