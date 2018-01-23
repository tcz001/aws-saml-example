package com.rackspace.saml;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.impl.ResponseMarshaller;
import org.opensaml.xml.util.XMLHelper;
import org.testng.annotations.Test;
import org.w3c.dom.Element;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

/**
 * User: twer
 * Date: 23/01/2018
 * Time: 2:30 PM
 */
public class SamlAssertionProducerTest {

    @Test
    public void testCreateSAMLResponse() throws Exception {


        SamlAssertionProducer producer = new SamlAssertionProducer();
        producer.setPrivateKeyLocation("/Users/twer/dev/security/hwIAM/saml-generator/saml.pkcs8");
        producer.setPublicKeyLocation("/Users/twer/dev/security/hwIAM/saml-generator/saml.crt");

        HashMap<String, List<String>> attributes = new HashMap<String, List<String>>();
        attributes.put("https://aws.amazon.com/SAML/Attributes/Role", Arrays.asList("arn:aws:iam::493306989415:role/ec2admin,arn:aws:iam::493306989415:saml-provider/mysaml"));

        Response responseInitial = producer.createSAMLResponse("", new DateTime(), attributes, "urn:tcz001.auth0.com", 5, "https://signin.aws.amazon.com/saml");

        ResponseMarshaller marshaller = new ResponseMarshaller();
        Element element = marshaller.marshall(responseInitial);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLHelper.writeNode(element, baos);
        String responseStr = new String(baos.toByteArray());

        System.out.println(responseStr);

        String encodedResponseStr = Base64.getEncoder().encodeToString(responseStr.getBytes());
        System.out.println(encodedResponseStr);

        String html = html(encodedResponseStr);
        File file = new File("test.html");
        FileWriter fileWriter = new FileWriter(file);
        fileWriter.write(html);
        fileWriter.close();
    }

    public static String html(String s){

        String targetURL = "https://signin.aws.amazon.com/saml";
        // Build the HTML File
        String htmlString="<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n";
        htmlString += "<html>\n";
        htmlString += "<head>\n";
        htmlString += "<title>SAML Test Assertion</title>\n";
        htmlString += "</head>\n";
        htmlString += "<body onload=\"submit_form();\">\n<form name=\"myform\" action=\"";
        htmlString += targetURL + "\" method=\"POST\">\n";
        htmlString += "<input type=\"hidden\" name=\"SAMLResponse\" value=\"";
        htmlString += s + "\">\n";
        htmlString += "</form>\n";
        htmlString += "<script language=\"javascript\">\n";
        htmlString += "function submit_form() {\n";
        htmlString += "document.myform.submit()\n";
        htmlString += "}\n";
        htmlString += "</script>\n";
        htmlString += "</body>\n";
        htmlString += "</html>\n";
        return htmlString;
    }
}