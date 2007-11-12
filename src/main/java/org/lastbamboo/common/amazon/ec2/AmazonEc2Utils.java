package org.lastbamboo.common.amazon.ec2;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collection;

public interface AmazonEc2Utils
    {
    
    /**
     * Accesses the public address for the EC2 instance.  This is necessary
     * because InetAddress.getLocalHost() will yeild the private, NATted
     * address.
     * 
     * @return The public address for the EC2 instance, or <code>null</code> if
     * there's an error accessing the address.
     */
    InetAddress getPublicAddress();

    /**
     * Returns the {@link InetSocketAddress}es of the instances with the
     * specified group ID.
     * 
     * @param groupId The group ID of the instances to look for.
     * @return A {@link Collection} of {@link InetAddress}es of all
     * instances matching the specified group ID.
     */
    Collection<InetAddress> getInstanceAddresses(String groupId);
    }
