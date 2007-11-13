package org.lastbamboo.common.amazon.ec2;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.xpath.XPathExpressionException;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.time.DateUtils;
import org.lastbamboo.common.amazon.stack.Base64;
import org.lastbamboo.common.http.client.HttpClientGetRequester;
import org.lastbamboo.common.util.NetworkUtils;
import org.lastbamboo.common.util.Pair;
import org.lastbamboo.common.util.RuntimeIoException;
import org.lastbamboo.common.util.UriUtils;
import org.lastbamboo.common.util.xml.XPathUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Utility methods for EC2. 
 */
public class AmazonEc2UtilsImpl implements AmazonEc2Utils
    {
    
    private static final Logger LOG = 
        LoggerFactory.getLogger(AmazonEc2UtilsImpl.class);
    
    private static InetAddress s_cachedAddress;

    private static long s_lastUpdateTime = 0L;

    private String m_accessKey;
    private String m_accessKeyId;
    
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    
    /**
     * Creates a new {@link AmazonEc2UtilsImpl} instance using the specified
     * Spring resources to look up the key and key ID.
     * 
     * @param accessKey The Spring {@link Resource} pointing to the access key.
     * @param accessKeyId The Spring {@link Resource} pointing to the access key 
     * id.
     */
    //public AmazonEc2UtilsImpl()
    //    {
        //this(getStringFromResource(accessKey), 
          //   getStringFromResource(accessKeyId));
      //  }
    
    private static String getStringFromResource(final Resource resource)
        {
        try
            {
            final File file = resource.getFile();
            final InputStream is = new FileInputStream(file);
            final String resourceString = IOUtils.toString(is).trim();
            LOG.debug("Returning resource: {}", resourceString);
            return resourceString;
            }
        catch (final IOException e)
            {
            LOG.error("Could not access key file: {}", resource, e);
            throw new RuntimeIoException("Could not read file: "+resource, e);
            }
        }

    /**
     * Creates a new {@link AmazonEc2UtilsImpl} instance using the specified
     * Amazon access key and access key ID.
     * 
     * @param accessKeyId The access key ID.
     * @param accessKey The access key.
     */
    public AmazonEc2UtilsImpl(final String accessKeyId, final String accessKey)
        {
        m_accessKeyId = accessKeyId;
        m_accessKey = accessKey;
        }
    
    /**
     * Creates a new {@link AmazonEc2UtilsImpl} instance that should only be
     * used for calls that don't require authentication.
     */
    public AmazonEc2UtilsImpl()
        {
        this("", "");
        }

    public void setAccessKeyIdResource(final Resource accessKeyIdResource)
        {
        this.m_accessKeyId = getStringFromResource(accessKeyIdResource);
        LOG.debug("Using key id: {}", this.m_accessKeyId);
        }
    
    public void setAccessKeyResource(final Resource accessKeyResource)
        {
        this.m_accessKey = getStringFromResource(accessKeyResource);
        LOG.debug("Using key: {}", this.m_accessKey);
        }
    
    public Collection<InetAddress> getInstanceAddresses(final String groupId)
        {
        final HttpClientGetRequester requester = new HttpClientGetRequester();
        final List<Pair<String, String>> params = 
            new LinkedList<Pair<String,String>>();
        
        params.add (UriUtils.pair ("Action", "DescribeInstances"));
        params.add (UriUtils.pair ("AWSAccessKeyId", m_accessKeyId));
        params.add (UriUtils.pair ("SignatureVersion", 1));
        
        final String format = "yyyy-MM-dd'T'HH:mm:ss'Z'";
        final SimpleDateFormat sdf = new SimpleDateFormat(format, Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
        final String date = sdf.format(new Date());
        LOG.debug("Using date: {}", date);
        params.add (UriUtils.pair ("Timestamp", date));
        params.add (UriUtils.pair ("Version", "2007-08-29"));
        
        
        final String sig = calculateRfc2104Hmac(params);
        
        // Note the signature is just another parameter -- it doesn't need
        // to be alphabetized because it's not, of course, used in 
        // calculating itself.
        params.add(UriUtils.pair("Signature", sig));
        
        // The trailing slash is necessary in the address.
        final String body = 
            requester.request("https://ec2.amazonaws.com/", params);
        LOG.debug("Received body:\n{}", body);
        
        return extractInetAddresses(groupId, body);
        }
    
    private Collection<InetAddress> extractInetAddresses(
        final String groupId, final String body)
        {
        // TODO: We should set the group ID here so we only query nodes running
        // with the group ID we're interested in.  For now, we only run a single
        // instance, so we're OK.
        final Collection<InetAddress> addresses = new LinkedList<InetAddress>();
        try
            {
            final XPathUtils xPath = XPathUtils.newXPath(body);
            final String path = 
                "/DescribeInstancesResponse/reservationSet/item/instancesSet/item/dnsName";
            final NodeList nodes = xPath.getNodes(path);
            for (int i = 0; i < nodes.getLength(); i++)
                {
                final Node node = nodes.item(i);
                final String urlString = node.getTextContent();
                try
                    {
                    addresses.add(InetAddress.getByName(urlString));
                    }
                catch (final UnknownHostException e)
                    {
                    LOG.warn("Unknown host: "+urlString, e);
                    }
                }
            }
        catch (final SAXException e)
            {
            LOG.error("SAX error", e);
            }
        catch (final IOException e)
            {
            LOG.error("IO error!", e);
            }
        catch (final XPathExpressionException e)
            {
            LOG.error("XPath error!!", e);
            }
        return addresses;
        }

    private String calculateRfc2104Hmac(
        final List<Pair<String, String>> params)
        {
        final Comparator<Pair<String, String>> comparator =  
            new Comparator<Pair<String,String>>()
            {

            public int compare(
                final Pair<String, String> param1, 
                final Pair<String, String> param2)
                {
                // Amazon orders without case.
                return param1.getFirst().compareToIgnoreCase(param2.getFirst());
                }
            };
        Collections.sort(params, comparator);
        final StringBuilder sb = new StringBuilder();
        for (final Pair<String, String> param : params)
            {
            sb.append(param.getFirst());
            sb.append(param.getSecond());
            }
        final String urlString = sb.toString();
        LOG.debug("Using string: {}", urlString);
        return calculateRfc2104Hmac(urlString);
        }

    /**
     * Computes RFC 2104-compliant HMAC signature.
     * 
     * @param data The data to be signed.
     * @param key The signing key.
     * @return The base64-encoded RFC 2104-compliant HMAC signature.
     */
    private String calculateRfc2104Hmac(final String data)
        {
        // get an hmac_sha1 key from the raw key bytes
        final SecretKeySpec signingKey = 
            new SecretKeySpec(this.m_accessKey.getBytes(),
                HMAC_SHA1_ALGORITHM);
        try
            {
            final Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
            mac.init(signingKey);

            // compute the hmac on input data bytes
            byte[] rawHmac = mac.doFinal(data.getBytes());

            // base64-encode the hmac
            return Base64.encodeBytes(rawHmac);
            }
        catch (final NoSuchAlgorithmException e)
            {
            LOG.error("No algorithm", e);
            throw new RuntimeException("Bad algorithm", e);
            }
        catch (final InvalidKeyException e)
            {
            LOG.error("Bad key", e);
            throw new RuntimeException("Bad key", e);
            }
        }
    
    public InetAddress getPublicAddress()
        {
        // First just check if we're even on Amazon -- we could be testing
        // locally, for example.
        LOG.debug("Getting public address");
        
        final long now = System.currentTimeMillis();
        if ((now - s_lastUpdateTime) < DateUtils.MILLIS_PER_MINUTE)
            {
            LOG.debug("Using cached address...");
            return s_cachedAddress;
            }
        
        // Check to see if we're running on EC2.  If we're not, we're probably 
        // testing.  This technique could be a problem if the EC2 internal 
        // addressing is ever different from 10.253.
        try
            {
            if (!NetworkUtils.getLocalHost().getHostAddress().startsWith("10.253"))
                {
                // Not running on EC2.  We might be testing, or this might be
                // a server running on another system.
                LOG.debug("Not running on EC2.");
                return NetworkUtils.getLocalHost();
                }
            }
        catch (final UnknownHostException e)
            {
            LOG.error("Could not get host.", e);
            return null;
            }
        final String url = "http://169.254.169.254/latest/meta-data/public-ipv4";
        final HttpClient client = new HttpClient();
        client.getHttpConnectionManager().getParams().setConnectionTimeout(
            10 * 1000);
        final GetMethod method = new GetMethod(url);
        try
            {
            LOG.debug("Executing method...");
            final int statusCode = client.executeMethod(method);
            if (statusCode != HttpStatus.SC_OK)
                {
                LOG.warn("ERROR ISSUING REQUEST:\n" + method.getStatusLine() + 
                    "\n" + method.getResponseBodyAsString());
                return null;
                }
            else
                {
                LOG.debug("Successfully received response...");
                }
            final String host = method.getResponseBodyAsString();
            LOG.debug("Got address: "+host);
            s_cachedAddress = InetAddress.getByName(host);
            s_lastUpdateTime = System.currentTimeMillis();
            return s_cachedAddress;
            }
        catch (final HttpException e)
            {
            LOG.error("Could not access EC2 service", e);
            return null;
            }
        catch (final IOException e)
            {
            LOG.error("Could not access EC2 service", e);
            return null;
            }
        finally 
            {
            method.releaseConnection();
            }
        }
    }
