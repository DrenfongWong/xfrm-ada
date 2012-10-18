with Ada.Text_IO;
with Ada.Streams;

with System.Storage_Elements;

with Interfaces.C;
with Interfaces.C.Extensions;

with Anet.Constants;

with xfrm_h;

with Xfrm.Sockets;

procedure Add_Sa
is

   use type Interfaces.Unsigned_16;
   use type Interfaces.Unsigned_32;
   use type Interfaces.C.unsigned;

   subtype Netlink_Buffer_Type is Ada.Streams.Stream_Element_Array (1 .. 512);

   XFRM_INF : constant Interfaces.C.Extensions.unsigned_long_long := not 0;

   procedure C_Memcpy
     (Dst : System.Address;
      Src : System.Address;
      Len : Interfaces.C.size_t);
   pragma Import (C, C_Memcpy, "memcpy");

   Buffer : Netlink_Buffer_Type := (others => 0);
   Hdr    : aliased Xfrm.Nlmsghdr_Type;
   for Hdr'Address use Buffer'Address;

   Sa_Addr : constant System.Address
     := Xfrm.Nlmsg_Data (Msg => Hdr'Access);
   Sa      : xfrm_h.xfrm_usersa_info;
   for Sa'Address use Sa_Addr;
   pragma Import (Ada, Sa);

   Enc_Rta_Addr : constant System.Address
     := Xfrm.Nlmsg_Data
       (Msg => Hdr'Access,
        Len => xfrm_h.xfrm_usersa_info'Object_Size / 8);
   Enc_Rta      : aliased Xfrm.Rtattr_Type;
   for Enc_Rta'Address use Enc_Rta_Addr;

   type Byte is mod 2 ** 8;
   type Byte_Array is array (Positive range <>) of Byte;

   Enc_Key_Len  : constant                               := 32;
   Enc_Key_Name : constant String                        := "aes";
   Enc_Key      : constant Byte_Array (1 .. Enc_Key_Len) := (others => 10);

   Int_Key_Len  : constant                               := 64;
   Int_Key_Name : constant String                        := "hmac(sha512)";
   Int_Key      : constant Byte_Array (1 .. Int_Key_Len) := (others => 11);

   Sock : Xfrm.Sockets.Xfrm_Socket_Type;
begin

   --  HDR

   Hdr.Nlmsg_Flags := Xfrm.NLM_F_REQUEST or Xfrm.NLM_F_ACK;
   Hdr.Nlmsg_Type  := Xfrm.Xfrm_Msg_Type'Enum_Rep (Xfrm.XFRM_MSG_NEWSA);
   Hdr.Nlmsg_Len   := Interfaces.Unsigned_32
     (Xfrm.Nlmsg_Length (Len => xfrm_h.xfrm_usersa_info'Object_Size / 8));

   --  SA

   Sa.reqid         := 1;
   Sa.saddr.a4      := 537878680;
   Sa.id.daddr.a4   := 1007640728;
   Sa.id.spi        := 123;
   Sa.id.proto      := Anet.Constants.IPPROTO_ESP;
   Sa.family        := 2;
   Sa.replay_window := 32;

   Sa.lft.soft_byte_limit          := XFRM_INF;
   Sa.lft.hard_byte_limit          := XFRM_INF;
   Sa.lft.soft_packet_limit        := XFRM_INF;
   Sa.lft.hard_packet_limit        := XFRM_INF;
   Sa.lft.soft_add_expires_seconds := XFRM_INF;
   Sa.lft.hard_add_expires_seconds := XFRM_INF;
   Sa.lft.soft_use_expires_seconds := 0;
   Sa.lft.hard_use_expires_seconds := 0;

   Encryption_Algorithm :
   declare
      Enc_Algo_Addr : constant System.Address := Xfrm.Rta_Data
        (Rta => Enc_Rta'Access);
      Enc_Algo      : xfrm_h.xfrm_algo;
      for Enc_Algo'Address use Enc_Algo_Addr;
      pragma Import (Ada, Enc_Algo);
   begin
      Enc_Rta.Rta_Type := xfrm_h.xfrm_attr_type_t'Pos (xfrm_h.XFRMA_ALG_CRYPT);
      Enc_Rta.Rta_Len  := Interfaces.C.unsigned_short
        (Xfrm.Rta_Length
           (Len => xfrm_h.xfrm_algo'Object_Size / 8) + Enc_Key_Len);

      Hdr.Nlmsg_Len := Hdr.Nlmsg_Len + Interfaces.Unsigned_32
        (Xfrm.Align (Len => Positive (Enc_Rta.Rta_Len)));

      Enc_Algo.alg_key_len := Enc_Key_Len * 8;
      Enc_Algo.alg_name (Enc_Algo.alg_name'First .. Enc_Key_Name'Length)
        := Interfaces.C.To_C (Enc_Key_Name);
      C_Memcpy (Dst => Enc_Algo.alg_key'Address,
                Src => Enc_Key'Address,
                Len => Enc_Key_Len);
   end Encryption_Algorithm;

   Integrity_Algorithm :
   declare
      use System.Storage_Elements;

      Int_Rta_Addr : constant System.Address
        := Enc_Rta_Addr + Storage_Offset
          (Xfrm.Align (Len => Positive (Enc_Rta.Rta_Len)));
      Int_Rta      : aliased Xfrm.Rtattr_Type;
      for Int_Rta'Address use Int_Rta_Addr;

      Int_Algo_Addr : constant System.Address := Xfrm.Rta_Data
        (Rta => Int_Rta'Access);
      Int_Algo      : xfrm_h.xfrm_algo;
      for Int_Algo'Address use Int_Algo_Addr;
      pragma Import (Ada, Int_Algo);
   begin
      Int_Rta.Rta_Type := xfrm_h.xfrm_attr_type_t'Pos
        (xfrm_h.XFRMA_ALG_AUTH);
      Int_Rta.Rta_Len  := Interfaces.C.unsigned_short
        (Xfrm.Rta_Length
           (Len => xfrm_h.xfrm_algo'Object_Size / 8) + Int_Key_Len);

      Hdr.Nlmsg_Len := Hdr.Nlmsg_Len + Interfaces.Unsigned_32
        (Xfrm.Align (Len => Positive (Int_Rta.Rta_Len)));

      Int_Algo.alg_key_len := Int_Key_Len * 8;
      Int_Algo.alg_name (Int_Algo.alg_name'First .. Int_Key_Name'Length)
        := Interfaces.C.To_C (Int_Key_Name);
      C_Memcpy (Dst => Int_Algo.alg_key'Address,
                Src => Int_Key'Address,
                Len => Int_Key_Len);
   end Integrity_Algorithm;

   Sock.Init;
   Sock.Bind (Address => 0);
   Sock.Send_Ack (Item => Buffer
                  (Buffer'First .. Ada.Streams.Stream_Element_Offset
                     (Hdr.Nlmsg_Len)));
   Ada.Text_IO.Put_Line ("OK");
end Add_Sa;
