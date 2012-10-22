with System.Storage_Elements;

with Interfaces.C.Strings;
with Interfaces.C.Extensions;

with Anet.Constants;

with xfrm_h;

with Xfrm.Thin;

package body Xfrm.Sockets
is

   use type Interfaces.Unsigned_16;
   use Xfrm.Thin;

   function C_Strerror
     (Errnum : Interfaces.C.int)
      return Interfaces.C.Strings.chars_ptr;
   pragma Import (C, C_Strerror, "strerror");

   procedure C_Memcpy
     (Dst : System.Address;
      Src : System.Address;
      Len : Interfaces.C.size_t);
   pragma Import (C, C_Memcpy, "memcpy");

   XFRM_INF : constant Interfaces.C.Extensions.unsigned_long_long := not 0;

   IPSEC_PROTO_ANY : constant := 255;

   -------------------------------------------------------------------------

   procedure Add_Policy
     (Socket : Xfrm_Socket_Type;
      Src    : Anet.IPv4_Addr_Type;
      Dst    : Anet.IPv4_Addr_Type;
      Reqid  : Positive)
   is
      use type Interfaces.Unsigned_32;

      Buffer : Ada.Streams.Stream_Element_Array (1 .. 512) := (others => 0);
      Hdr    : aliased Nlmsghdr_Type;
      for Hdr'Address use Buffer'Address;

      Policy_Addr : constant System.Address := Nlmsg_Data (Msg => Hdr'Access);
      Policy      : xfrm_h.xfrm_userpolicy_info;
      for Policy'Address use Policy_Addr;
      pragma Import (Ada, Policy);

      Rta_Addr : constant System.Address
        := Nlmsg_Data (Msg => Hdr'Access,
                       Len => xfrm_h.xfrm_userpolicy_info'Object_Size / 8);
      Rta      : aliased Rtattr_Type;
      for Rta'Address use Rta_Addr;

      Tmpl_Addr : constant System.Address
        := Rta_Data (Rta => Rta'Access);
      Tmpl      : xfrm_h.xfrm_user_tmpl;
      for Tmpl'Address use Tmpl_Addr;
      pragma Import (Ada, Tmpl);
   begin

      --  HDR

      Hdr.Nlmsg_Flags := NLM_F_REQUEST or NLM_F_ACK;
      Hdr.Nlmsg_Type  := Xfrm_Msg_Type'Enum_Rep (XFRM_MSG_NEWPOLICY);
      Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
        (Nlmsg_Length (Len => xfrm_h.xfrm_userpolicy_info'Object_Size / 8));

      --  Policy

      C_Memcpy (Dst => Policy.sel.saddr.a4'Address,
                Src => Src'Address,
                Len => Src'Length);
      C_Memcpy (Dst => Policy.sel.daddr.a4'Address,
                Src => Dst'Address,
                Len => Dst'Length);
      Policy.sel.family      := 2;
      Policy.sel.prefixlen_d := 32;
      Policy.sel.prefixlen_s := 32;
      Policy.priority        := 3843;
      Policy.action          := XFRM_POLICY_ALLOW;
      Policy.share           := Xfrm_Share_Type'Pos (XFRM_SHARE_ANY);

      Policy.lft.soft_byte_limit   := XFRM_INF;
      Policy.lft.soft_packet_limit := XFRM_INF;
      Policy.lft.hard_byte_limit   := XFRM_INF;
      Policy.lft.hard_packet_limit := XFRM_INF;

      --  RTA

      Rta.Rta_Type  := xfrm_h.xfrm_attr_type_t'Pos (xfrm_h.XFRMA_TMPL);
      Rta.Rta_Len   := Interfaces.C.unsigned_short
        (Rta_Length (Len => xfrm_h.xfrm_user_tmpl'Object_Size / 8));
      Hdr.Nlmsg_Len := Hdr.Nlmsg_Len + Interfaces.Unsigned_32
        (Align (Len => Positive (Rta.Rta_Len)));

      --  Template

      Tmpl.reqid    := Interfaces.C.unsigned (Reqid);
      Tmpl.id.proto := Anet.Constants.IPPROTO_ESP;
      Tmpl.aalgos   := not 0;
      Tmpl.ealgos   := not 0;
      Tmpl.calgos   := not 0;
      Tmpl.mode     := XFRM_MODE_TRANSPORT;
      Tmpl.family   := 2;

      Socket.Send_Ack (Item => Buffer (Buffer'First ..
                         Ada.Streams.Stream_Element_Offset (Hdr.Nlmsg_Len)));
   end Add_Policy;

   -------------------------------------------------------------------------

   procedure Add_State
     (Socket        : Xfrm_Socket_Type;
      Src           : Anet.IPv4_Addr_Type;
      Dst           : Anet.IPv4_Addr_Type;
      Reqid         : Positive;
      Spi           : Positive;
      Enc_Key       : Anet.Byte_Array;
      Enc_Alg       : String;
      Int_Key       : Anet.Byte_Array;
      Int_Alg       : String;
      Lifetime_Soft : Natural := 0;
      Lifetime_Hard : Natural := 0)
   is
      use type Interfaces.Unsigned_32;
      use type Interfaces.C.unsigned;

      Buffer : Ada.Streams.Stream_Element_Array (1 .. 512) := (others => 0);
      Hdr    : aliased Nlmsghdr_Type;
      for Hdr'Address use Buffer'Address;

      Sa_Addr : constant System.Address := Nlmsg_Data (Msg => Hdr'Access);
      Sa      : xfrm_h.xfrm_usersa_info;
      for Sa'Address use Sa_Addr;
      pragma Import (Ada, Sa);

      Enc_Rta_Addr : constant System.Address
        := Nlmsg_Data (Msg => Hdr'Access,
                       Len => xfrm_h.xfrm_usersa_info'Object_Size / 8);
      Enc_Rta      : aliased Rtattr_Type;
      for Enc_Rta'Address use Enc_Rta_Addr;
   begin

      --  HDR

      Hdr.Nlmsg_Flags := NLM_F_REQUEST or NLM_F_ACK;
      Hdr.Nlmsg_Type  := Xfrm_Msg_Type'Enum_Rep (XFRM_MSG_NEWSA);
      Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
        (Nlmsg_Length (Len => xfrm_h.xfrm_usersa_info'Object_Size / 8));

      --  SA

      C_Memcpy (Dst => Sa.saddr.a4'Address,
                Src => Src'Address,
                Len => Src'Length);
      C_Memcpy (Dst => Sa.id.daddr.a4'Address,
                Src => Dst'Address,
                Len => Dst'Length);
      Sa.reqid         := Interfaces.C.unsigned (Reqid);
      Sa.id.spi        := Interfaces.C.unsigned (Spi);
      Sa.id.proto      := Anet.Constants.IPPROTO_ESP;
      Sa.family        := 2;
      Sa.replay_window := 32;

      if Lifetime_Soft /= 0 then
         Sa.lft.soft_add_expires_seconds
           := Interfaces.C.Extensions.unsigned_long_long (Lifetime_Soft);
      else
         Sa.lft.soft_add_expires_seconds := XFRM_INF;
      end if;
      if Lifetime_Hard /= 0 then
         Sa.lft.hard_add_expires_seconds
           := Interfaces.C.Extensions.unsigned_long_long (Lifetime_Hard);
      else
         Sa.lft.hard_add_expires_seconds := XFRM_INF;
      end if;

      Sa.lft.soft_byte_limit          := XFRM_INF;
      Sa.lft.hard_byte_limit          := XFRM_INF;
      Sa.lft.soft_packet_limit        := XFRM_INF;
      Sa.lft.hard_packet_limit        := XFRM_INF;
      Sa.lft.soft_use_expires_seconds := 0;
      Sa.lft.hard_use_expires_seconds := 0;

      Encryption_Algorithm :
      declare
         Enc_Algo_Addr : constant System.Address := Rta_Data
           (Rta => Enc_Rta'Access);
         Enc_Algo      : xfrm_h.xfrm_algo;
         for Enc_Algo'Address use Enc_Algo_Addr;
         pragma Import (Ada, Enc_Algo);
      begin
         Enc_Rta.Rta_Type := xfrm_h.xfrm_attr_type_t'Pos
           (xfrm_h.XFRMA_ALG_CRYPT);
         Enc_Rta.Rta_Len  := Interfaces.C.unsigned_short
           (Rta_Length (Len => xfrm_h.xfrm_algo'Object_Size / 8)
            + Enc_Key'Length);

         Hdr.Nlmsg_Len := Hdr.Nlmsg_Len + Interfaces.Unsigned_32
           (Align (Len => Positive (Enc_Rta.Rta_Len)));

         Enc_Algo.alg_key_len := Enc_Key'Length * 8;
         Enc_Algo.alg_name (Enc_Algo.alg_name'First .. Enc_Alg'Length)
           := Interfaces.C.To_C (Enc_Alg);
         C_Memcpy (Dst => Enc_Algo.alg_key'Address,
                   Src => Enc_Key'Address,
                   Len => Enc_Key'Length);
      end Encryption_Algorithm;

      Integrity_Algorithm :
      declare
         use System.Storage_Elements;

         Int_Rta_Addr : constant System.Address
           := Enc_Rta_Addr + Storage_Offset
             (Align (Len => Positive (Enc_Rta.Rta_Len)));
         Int_Rta      : aliased Rtattr_Type;
         for Int_Rta'Address use Int_Rta_Addr;

         Int_Algo_Addr : constant System.Address := Rta_Data
           (Rta => Int_Rta'Access);
         Int_Algo      : xfrm_h.xfrm_algo;
         for Int_Algo'Address use Int_Algo_Addr;
         pragma Import (Ada, Int_Algo);
      begin
         Int_Rta.Rta_Type := xfrm_h.xfrm_attr_type_t'Pos
           (xfrm_h.XFRMA_ALG_AUTH);
         Int_Rta.Rta_Len  := Interfaces.C.unsigned_short
           (Rta_Length (Len => xfrm_h.xfrm_algo'Object_Size / 8)
            + Int_Key'Length);

         Hdr.Nlmsg_Len := Hdr.Nlmsg_Len + Interfaces.Unsigned_32
           (Align (Len => Positive (Int_Rta.Rta_Len)));

         Int_Algo.alg_key_len := Int_Key'Length * 8;
         Int_Algo.alg_name (Int_Algo.alg_name'First .. Int_Alg'Length)
           := Interfaces.C.To_C (Int_Alg);
         C_Memcpy (Dst => Int_Algo.alg_key'Address,
                   Src => Int_Key'Address,
                   Len => Int_Key'Length);
      end Integrity_Algorithm;

      Socket.Send_Ack (Item => Buffer (Buffer'First ..
                         Ada.Streams.Stream_Element_Offset (Hdr.Nlmsg_Len)));
   end Add_State;

   -------------------------------------------------------------------------

   procedure Delete_Policy
     (Socket : Xfrm_Socket_Type;
      Src    : Anet.IPv4_Addr_Type;
      Dst    : Anet.IPv4_Addr_Type)
   is
      Buffer : Ada.Streams.Stream_Element_Array (1 .. 80) := (others => 0);
      Hdr    : aliased Nlmsghdr_Type;
      for Hdr'Address use Buffer'Address;

      Policy_Id_Addr : constant System.Address := Nlmsg_Data
        (Msg => Hdr'Access);
      Policy_Id      : xfrm_h.xfrm_userpolicy_id;
      for Policy_Id'Address use Policy_Id_Addr;
      pragma Import (Ada, Policy_Id);
   begin

      --  HDR

      Hdr.Nlmsg_Flags := NLM_F_REQUEST or NLM_F_ACK;
      Hdr.Nlmsg_Type  := Xfrm_Msg_Type'Enum_Rep (XFRM_MSG_DELPOLICY);
      Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
        (Nlmsg_Length (Len => xfrm_h.xfrm_userpolicy_id'Object_Size / 8));

      --  Policy ID

      C_Memcpy (Dst => Policy_Id.sel.saddr.a4'Address,
                Src => Src'Address,
                Len => Src'Length);
      C_Memcpy (Dst => Policy_Id.sel.daddr.a4'Address,
                Src => Dst'Address,
                Len => Dst'Length);
      Policy_Id.sel.family      := 2;
      Policy_Id.sel.prefixlen_d := 32;
      Policy_Id.sel.prefixlen_s := 32;

      Socket.Send_Ack (Item => Buffer (Buffer'First ..
                         Ada.Streams.Stream_Element_Offset (Hdr.Nlmsg_Len)));
   end Delete_Policy;

   -------------------------------------------------------------------------

   procedure Delete_State
     (Socket : Xfrm_Socket_Type;
      Dst    : Anet.IPv4_Addr_Type;
      Spi    : Positive)
   is
      Buffer : Ada.Streams.Stream_Element_Array (1 .. 40) := (others => 0);
      Hdr    : aliased Nlmsghdr_Type;
      for Hdr'Address use Buffer'Address;

      Sa_Id_Addr : constant System.Address := Nlmsg_Data (Msg => Hdr'Access);
      Sa_Id      : xfrm_h.xfrm_usersa_id;
      for Sa_Id'Address use Sa_Id_Addr;
      pragma Import (Ada, Sa_Id);
   begin

      --  HDR

      Hdr.Nlmsg_Flags := NLM_F_REQUEST or NLM_F_ACK;
      Hdr.Nlmsg_Type  := Xfrm_Msg_Type'Enum_Rep (XFRM_MSG_DELSA);
      Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
        (Nlmsg_Length (Len => xfrm_h.xfrm_usersa_id'Object_Size / 8));

      --  SA ID

      C_Memcpy (Dst => Sa_Id.daddr.a4'Address,
                Src => Dst'Address,
                Len => Dst'Length);
      Sa_Id.proto    := Anet.Constants.IPPROTO_ESP;
      Sa_Id.spi      := Interfaces.C.unsigned (Spi);
      Sa_Id.family   := 2;

      Socket.Send_Ack (Item => Buffer (Buffer'First ..
                         Ada.Streams.Stream_Element_Offset (Hdr.Nlmsg_Len)));
   end Delete_State;

   -------------------------------------------------------------------------

   procedure Flush_Policies (Socket : Xfrm_Socket_Type)
   is
      Buffer : Ada.Streams.Stream_Element_Array (1 .. 16) := (others => 0);
      Hdr    : aliased Nlmsghdr_Type;
      for Hdr'Address use Buffer'Address;
   begin
      Hdr.Nlmsg_Flags := NLM_F_REQUEST or NLM_F_ACK;
      Hdr.Nlmsg_Type  := Xfrm_Msg_Type'Enum_Rep (XFRM_MSG_FLUSHPOLICY);
      Hdr.Nlmsg_Len   := Interfaces.Unsigned_32 (Nlmsg_Length (Len => 0));

      Socket.Send_Ack (Item => Buffer (Buffer'First ..
                         Ada.Streams.Stream_Element_Offset (Hdr.Nlmsg_Len)));
   end Flush_Policies;

   -------------------------------------------------------------------------

   procedure Flush_States (Socket : Xfrm_Socket_Type)
   is
      Buffer : Ada.Streams.Stream_Element_Array (1 .. 17) := (others => 0);
      Hdr    : aliased Nlmsghdr_Type;
      for Hdr'Address use Buffer'Address;

      Flush_Addr : constant System.Address := Nlmsg_Data (Msg => Hdr'Access);
      Flush      : xfrm_h.xfrm_usersa_flush;
      for Flush'Address use Flush_Addr;
      pragma Import (Ada, Flush);
   begin

      --  HDR

      Hdr.Nlmsg_Flags := NLM_F_REQUEST or NLM_F_ACK;
      Hdr.Nlmsg_Type  := Xfrm_Msg_Type'Enum_Rep (XFRM_MSG_FLUSHSA);
      Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
        (Nlmsg_Length (Len => xfrm_h.xfrm_usersa_flush'Object_Size / 8));

      --  Flush

      Flush.proto := IPSEC_PROTO_ANY;

      Socket.Send_Ack (Item => Buffer (Buffer'First ..
                         Ada.Streams.Stream_Element_Offset (Hdr.Nlmsg_Len)));
   end Flush_States;

   -------------------------------------------------------------------------

   procedure Init (Socket : in out Xfrm_Socket_Type)
   is
   begin
      Anet.Sockets.Netlink.Raw_Socket_Type (Socket).Init
        (Protocol => Anet.Sockets.Netlink.Proto_Netlink_Xfrm);
      Socket.Bind (Address => 0);
   end Init;

   -------------------------------------------------------------------------

   procedure Send_Ack
     (Socket : Xfrm_Socket_Type;
      Item   : Ada.Streams.Stream_Element_Array)
   is
      Buffer : Ada.Streams.Stream_Element_Array (1 .. 1024);
      Last   : Ada.Streams.Stream_Element_Offset;
   begin
      Socket.Send (Item);
      Socket.Receive (Item => Buffer,
                      Last => Last);

      declare
         Recv_Buffer : Ada.Streams.Stream_Element_Array
           := Buffer (Buffer'First .. Last);
         Recv_Hdr    : aliased Nlmsghdr_Type;
         for Recv_Hdr'Address use Recv_Buffer'Address;
      begin
         if not Nlmsg_Ok
           (Msg => Recv_Hdr,
            Len => Natural (Last))
         then
            raise Xfrm_Error with "Invalid reply from kernel";
         end if;

         if Recv_Hdr.Nlmsg_Type = NLMSG_ERROR then
            declare
               use type Interfaces.C.int;

               Err_Addr : constant System.Address
                 := Nlmsg_Data (Msg => Recv_Hdr'Access);
               Err      : Nlmsgerr_Type;
               for Err'Address use Err_Addr;
            begin
               if Err.Error /= 0 then
                  raise Xfrm_Error with Interfaces.C.Strings.Value
                    (C_Strerror (Errnum => -Err.Error));
               else

                  --  OK.

                  return;
               end if;
            end;
         else
            raise Xfrm_Error with "Request not acknowledged";
         end if;
      end;
   end Send_Ack;

end Xfrm.Sockets;
