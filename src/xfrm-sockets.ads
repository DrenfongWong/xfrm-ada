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

with Ada.Streams;

with Interfaces;

with Anet.Sockets.Netlink;

package Xfrm.Sockets
is

   type Direction_Type is
     (Direction_In,
      Direction_Fwd,
      Direction_Out);
   --  Policy directions.

   type Mode_Type is
     (Mode_Transport,
      Mode_Tunnel);
   --  IPsec modes.

   type Xfrm_Socket_Type is new
     Anet.Sockets.Netlink.Raw_Socket_Type with private;
   --  Netlink/XFRM socket.

   procedure Init (Socket : in out Xfrm_Socket_Type);
   --  Initialize given XFRM socket.

   procedure Send_Ack
     (Socket     : Xfrm_Socket_Type;
      Err_Prefix : String;
      Item       : Ada.Streams.Stream_Element_Array);
   --  Send given data to the XFRM subsystem, wait for ACK from the kernel.
   --  Raises an exception with specified error message prefix if the operation
   --  was not successful.

   procedure Add_Policy
     (Socket    : Xfrm_Socket_Type;
      Mode      : Mode_Type;
      Sel_Src   : Anet.IPv4_Addr_Type;
      Sel_Dst   : Anet.IPv4_Addr_Type;
      Reqid     : Interfaces.Unsigned_32;
      Direction : Direction_Type);
   --  Add XFRM policy with given parameters.

   procedure Delete_Policy
     (Socket    : Xfrm_Socket_Type;
      Sel_Src   : Anet.IPv4_Addr_Type;
      Sel_Dst   : Anet.IPv4_Addr_Type;
      Direction : Direction_Type);
   --  Delete XFRM policy.

   procedure Flush_Policies (Socket : Xfrm_Socket_Type);
   --  Flush SPD.

   procedure Add_State
     (Socket        : Xfrm_Socket_Type;
      Mode          : Mode_Type;
      Src           : Anet.IPv4_Addr_Type;
      Dst           : Anet.IPv4_Addr_Type;
      Reqid         : Interfaces.Unsigned_32;
      Spi           : Interfaces.Unsigned_32;
      Enc_Key       : Anet.Byte_Array;
      Enc_Alg       : String;
      Int_Key       : Anet.Byte_Array;
      Int_Alg       : String;
      Lifetime_Soft : Interfaces.Unsigned_64 := 0;
      Lifetime_Hard : Interfaces.Unsigned_64 := 0);
   --  Add SA with given parameters. The lifetime parameters specify the amount
   --  in seconds of the soft/hard expire timeout of the SA; the default is 0
   --  (= no timeout).

   procedure Delete_State
     (Socket : Xfrm_Socket_Type;
      Dst    : Anet.IPv4_Addr_Type;
      Spi    : Interfaces.Unsigned_32);
   --  Delete SA state with given parameters.

   procedure Flush_States (Socket : Xfrm_Socket_Type);
   --  Flush SAD.

   Xfrm_Error : exception;

private

   type Xfrm_Socket_Type is new
     Anet.Sockets.Netlink.Raw_Socket_Type with null record;

end Xfrm.Sockets;
