with System;

with GNAT.Byte_Swapping;

package body Xfrm.Byte_Swapping is

   use type System.Bit_Order;

   function Swapped is new
     GNAT.Byte_Swapping.Swapped4 (Item => Interfaces.Unsigned_32);

   -------------------------------------------------------------------------

   function Host_To_Network
     (Input : Interfaces.Unsigned_32)
      return Interfaces.Unsigned_32
   is
   begin
      if System.Default_Bit_Order = System.Low_Order_First then
         return Swapped (Input);
      else
         return Input;
      end if;
   end Host_To_Network;

end Xfrm.Byte_Swapping;
