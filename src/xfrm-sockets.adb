with Interfaces.C.Strings;

package body Xfrm.Sockets
is

   function C_Strerror
     (Errnum : Interfaces.C.int)
      return Interfaces.C.Strings.chars_ptr;
   pragma Import (C, C_Strerror, "strerror");

   -------------------------------------------------------------------------

   procedure Send_Ack
     (Socket : Xfrm_Socket_Type;
      Item   : Ada.Streams.Stream_Element_Array)
   is
      use type Interfaces.Unsigned_16;

      Buffer : Ada.Streams.Stream_Element_Array (1 .. 1024);
      Last   : Ada.Streams.Stream_Element_Offset;
   begin
      Socket.Send (Item);
      Socket.Receive (Item => Buffer,
                      Last => Last);

      declare
         Recv_Buffer : Ada.Streams.Stream_Element_Array
           := Buffer (Buffer'First .. Last);
         Recv_Hdr    : aliased Xfrm.Nlmsghdr_Type;
         for Recv_Hdr'Address use Recv_Buffer'Address;
      begin
         if not Xfrm.Nlmsg_Ok
           (Msg => Recv_Hdr,
            Len => Natural (Last))
         then
            raise Xfrm_Error with "Invalid reply from kernel";
         end if;

         if Recv_Hdr.Nlmsg_Type = Xfrm.NLMSG_ERROR then
            declare
               use type Interfaces.C.int;

               Err_Addr : constant System.Address
                 := Xfrm.Nlmsg_Data (Msg => Recv_Hdr'Access);
               Err      : Xfrm.Nlmsgerr_Type;
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
