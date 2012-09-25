--
--  Copyright (C) 2012 secunet Security Networks AG
--  Copyright (C) 2012 Reto Buerki <reet@codelabs.ch>
--  Copyright (C) 2012 Adrian-Ken Rueegsegger <ken@codelabs.ch>
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

with System.Storage_Elements;

package body Xfrm
is

   -------------------------------------------------------------------------

   function Align (Len : Natural) return Natural
   is
      use type Interfaces.Unsigned_32;

      Tmp : Interfaces.Unsigned_32 := Interfaces.Unsigned_32 (Len);
   begin
      return Natural ((Tmp + ALIGNTO - 1) and not (ALIGNTO - 1));
   end Align;

   -------------------------------------------------------------------------

   function Nlmsg_Data (Msg : access Nlmsghdr_Type) return System.Address
   is
      use System.Storage_Elements;
   begin
      return Msg.all'Address + Storage_Offset (Nlmsg_Length (Len => 0));
   end Nlmsg_Data;

   -------------------------------------------------------------------------

   function Nlmsg_Data
     (Msg : access Nlmsghdr_Type;
      Len : Natural)
      return System.Address
   is
      use System.Storage_Elements;
   begin
      return Nlmsg_Data (Msg => Msg) + Storage_Offset (Align (Len => Len));
   end Nlmsg_Data;

   -------------------------------------------------------------------------

   function Nlmsg_Hdrlen return Natural
   is
   begin
      return Align (Nlmsghdr_Type'Size / 8);
   end Nlmsg_Hdrlen;

   -------------------------------------------------------------------------

   function Nlmsg_Length (Len : Natural) return Natural
   is
   begin
      return Len + Align (Len => Nlmsg_Hdrlen);
   end Nlmsg_Length;

   -------------------------------------------------------------------------

   function Nlmsg_Ok
     (Msg : Nlmsghdr_Type;
      Len : Natural)
      return Boolean
   is
      use Interfaces;

      Len_32     : constant Unsigned_32 := Unsigned_32 (Len);
      Nlmsg_Size : constant Unsigned_32 := Nlmsghdr_Type'Size / 8;
   begin
      return Len_32 >= Nlmsg_Size
        and then Msg.Nlmsg_Len >= Nlmsg_Size
        and then Msg.Nlmsg_Len <= Len_32;
   end Nlmsg_Ok;

   -------------------------------------------------------------------------

   function Nlmsg_Payload
     (Msg : Nlmsghdr_Type;
      Len : Natural)
      return Natural
   is
   begin
      return Natural (Msg.Nlmsg_Len) - Nlmsg_Length (Len => Len);
   end Nlmsg_Payload;

   -------------------------------------------------------------------------

   function Nlmsg_Space (Len : Natural) return Natural
   is
   begin
      return Align (Len => Nlmsg_Length (Len => Len));
   end Nlmsg_Space;

   -------------------------------------------------------------------------

   function Rta_Data (Rta : access Rtattr_Type) return System.Address
   is
      use System.Storage_Elements;
   begin
      return Rta.all'Address + Storage_Offset (Rta_Length (Len => 0));
   end Rta_Data;

   -------------------------------------------------------------------------

   function Rta_Length (Len : Natural) return Natural
   is
   begin
      return Align (Len => Rtattr_Type'Size / 8) + Len;
   end Rta_Length;

   -------------------------------------------------------------------------

   procedure Rta_Next
     (Rta     : access Rtattr_Type;
      Attrlen : in out Natural;
      Address :    out System.Address)
   is
      use System.Storage_Elements;
   begin
      Attrlen := Attrlen - Align (Len => Natural (Rta.Rta_Len));

      Address := Rta.all'Address + Storage_Offset
        (Align (Len => Natural (Rta.Rta_Len)));
   end Rta_Next;

   -------------------------------------------------------------------------

   function Rta_Ok
     (Rta : Rtattr_Type;
      Len : Natural)
      return Boolean
   is
      use Interfaces;
      use type Interfaces.C.unsigned_short;

      Attr_Size : constant Unsigned_32 := Rtattr_Type'Size / 8;
   begin
      return Unsigned_32 (Len) >= Attr_Size
        and then Unsigned_32 (Rta.Rta_Len) >= Attr_Size
        and then Rta.Rta_Len <= Interfaces.C.unsigned_short (Len);
   end Rta_Ok;

end Xfrm;
