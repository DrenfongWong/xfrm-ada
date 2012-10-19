with System;

with Interfaces.C;

package Xfrm
is
   pragma Pure;

   type Nlmsghdr_Type is record
      Nlmsg_Len   : Interfaces.Unsigned_32;
      --  Length of message including header.
      Nlmsg_Type  : Interfaces.Unsigned_16;
      --  Message content.
      Nlmsg_Flags : Interfaces.Unsigned_16;
      --  Additional flags.
      Nlmsg_Seq   : Interfaces.Unsigned_32;
      --  Sequence number.
      Nlmsg_Pid   : Interfaces.Unsigned_32;
      --  Sending process port ID.
   end record;
   pragma Convention (C, Nlmsghdr_Type);

   for Nlmsghdr_Type'Size use 128;
   for Nlmsghdr_Type'Alignment use 1;

   type Nlmsgerr_Type is record
      Error : Interfaces.C.int;
      Msg   : Nlmsghdr_Type;
   end record;
   pragma Convention (C, Nlmsgerr_Type);

   -------------------
   -- Netlink flags --
   -------------------

   NLM_F_REQUEST : constant := 1; --  It is a request message.
   NLM_F_MULTI   : constant := 2; --  Multipart message.
   NLM_F_ACK     : constant := 4; --  Reply with ack, with zero or error code.
   NLM_F_ECHO    : constant := 8; --  Echo this request.

   type Rtattr_Type is record
      Rta_Len  : Interfaces.C.unsigned_short;
      Rta_Type : Interfaces.C.unsigned_short;
   end record;
   pragma Convention (C, Rtattr_Type);
   --  Generic structure for encapsulation of optional route information.

   NLMSG_NOOP    : constant := 16#01#;
   NLMSG_ERROR   : constant := 16#02#;
   NLMSG_DONE    : constant := 16#03#;
   NLMSG_OVERRUN : constant := 16#04#;

   ------------------------
   -- NLMSG/RTA handling --
   ------------------------

   ALIGNTO : constant := 4;
   --  Alignment.

   function Align (Len : Natural) return Natural;

   function Nlmsg_Space (Len : Natural) return Natural;

   function Nlmsg_Payload
     (Msg : Nlmsghdr_Type;
      Len : Natural)
      return Natural;

   function Nlmsg_Ok
     (Msg : Nlmsghdr_Type;
      Len : Natural)
      return Boolean;

   function Nlmsg_Hdrlen return Natural;

   function Nlmsg_Length (Len : Natural) return Natural;

   function Nlmsg_Data (Msg : access Nlmsghdr_Type) return System.Address;

   function Nlmsg_Data
     (Msg : access Nlmsghdr_Type;
      Len : Natural)
      return System.Address;

   function Rta_Length (Len : Natural) return Natural;

   function Rta_Ok
     (Rta : Rtattr_Type;
      Len : Natural)
      return Boolean;

   function Rta_Data (Rta : access Rtattr_Type) return System.Address;

   procedure Rta_Next
     (Rta     : access Rtattr_Type;
      Attrlen : in out Natural;
      Address :    out System.Address);

   ----------
   -- XFRM --
   ----------

   type Xfrm_Msg_Type is
     (XFRM_MSG_NEWSA,
      XFRM_MSG_DELSA,
      XFRM_MSG_GETSA,
      XFRM_MSG_NEWPOLICY,
      XFRM_MSG_DELPOLICY,
      XFRM_MSG_GETPOLICY,
      XFRM_MSG_ALLOCSPI,
      XFRM_MSG_ACQUIRE,
      XFRM_MSG_EXPIRE,
      XFRM_MSG_UPDPOLICY,
      XFRM_MSG_UPDSA,
      XFRM_MSG_POLEXPIRE,
      XFRM_MSG_FLUSHSA,
      XFRM_MSG_FLUSHPOLICY,
      XFRM_MSG_NEWAE,
      XFRM_MSG_GETAE,
      XFRM_MSG_REPORT,
      XFRM_MSG_MIGRATE,
      XFRM_MSG_NEWSADINFO,
      XFRM_MSG_GETSADINFO,
      XFRM_MSG_NEWSPDINFO,
      XFRM_MSG_GETSPDINFO,
      XFRM_MSG_MAPPING);
   --  Netlink/XFRM configuration messages.

   for Xfrm_Msg_Type use
     (XFRM_MSG_NEWSA       => 16,
      XFRM_MSG_DELSA       => 17,
      XFRM_MSG_GETSA       => 18,
      XFRM_MSG_NEWPOLICY   => 19,
      XFRM_MSG_DELPOLICY   => 20,
      XFRM_MSG_GETPOLICY   => 21,
      XFRM_MSG_ALLOCSPI    => 22,
      XFRM_MSG_ACQUIRE     => 23,
      XFRM_MSG_EXPIRE      => 24,
      XFRM_MSG_UPDPOLICY   => 25,
      XFRM_MSG_UPDSA       => 26,
      XFRM_MSG_POLEXPIRE   => 27,
      XFRM_MSG_FLUSHSA     => 28,
      XFRM_MSG_FLUSHPOLICY => 29,
      XFRM_MSG_NEWAE       => 30,
      XFRM_MSG_GETAE       => 31,
      XFRM_MSG_REPORT      => 32,
      XFRM_MSG_MIGRATE     => 33,
      XFRM_MSG_NEWSADINFO  => 34,
      XFRM_MSG_GETSADINFO  => 35,
      XFRM_MSG_NEWSPDINFO  => 36,
      XFRM_MSG_GETSPDINFO  => 37,
      XFRM_MSG_MAPPING     => 38);

   type Xfrm_Share_Type is
     (XFRM_SHARE_ANY,     --  No limitations.
      XFRM_SHARE_SESSION, --  For this session only.
      XFRM_SHARE_USER,    --  For this user only.
      XFRM_SHARE_UNIQUE); --  Use once.

   XFRM_POLICY_ALLOW : constant := 0;

   XFRM_MODE_TRANSPORT : constant := 0;

end Xfrm;
