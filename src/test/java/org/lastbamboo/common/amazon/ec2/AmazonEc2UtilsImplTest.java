package org.lastbamboo.common.amazon.ec2;

import static org.junit.Assert.*;

import java.net.InetAddress;
import java.util.Collection;

import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * Test for Amazon EC2 utlities.
 */
public class AmazonEc2UtilsImplTest
    {

    @Test public void testDescribeInstances() throws Exception
        {

        final String[] contexts = 
            {
            "amazonEc2Beans.xml"
            };
        final ClassPathXmlApplicationContext context = 
            new ClassPathXmlApplicationContext(contexts);
        
        final AmazonEc2Utils utils =
            (AmazonEc2Utils) context.getBean("amazonEc2Utils");
        
        final Collection<InetAddress> instances = 
            utils.getInstanceAddresses("sip-turn");
        
        //assertEquals(
          //  InetAddress.getByName("ec2-67-202-6-199.z-1.compute-1.amazonaws.com"), 
            //instances.iterator().next());
        }
    }
