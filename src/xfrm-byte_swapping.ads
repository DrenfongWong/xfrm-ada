with Interfaces;

package Xfrm.Byte_Swapping is

   function Host_To_Network
     (Input : Interfaces.Unsigned_32)
      return Interfaces.Unsigned_32;
   --  Convert given input from host byte order to network byte order.

end Xfrm.Byte_Swapping;
