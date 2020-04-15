package de.msesterhenn.sophos_utm_cleanup;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import org.apache.commons.lang3.SerializationUtils;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

public class Main {
	

    // one instance, reuse
    static CloseableHttpClient httpClient = null;
    
    static BufferedReader reader =
            new BufferedReader(new InputStreamReader(System.in));
    
    static Gson gson = new Gson();
    static JsonParser jsonparser = new JsonParser();

	public static void main(String[] args) {
		
		try 
		{
			httpClient = HttpClients
			        .custom()
			        .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
			        .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
			        .build();
		} 
		catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e1) 
		{
			e1.printStackTrace();
		}
		
		String apibase = "";
		String apikey = "";

		try 
		{
			System.out.println("Enter UTM API Base (e.g. https://192.168.30.10:4444/api/) :");
			
			apibase = reader.readLine();

			System.out.println("Enter UTM API Key:");
		
			apikey = reader.readLine();
		} 
		catch (IOException e) 
		{
			e.printStackTrace();
		}
		
		
		HashMap<String, String> headers = new HashMap<String, String>();
		headers.put("Accept", "application/json");
		headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(("token:" + apikey).getBytes()));
		
		
		ArrayList<String> networkItemsToDelete = new ArrayList<String>();
        
		try 
		{
			String networkList = sendGet(apibase + "/objects/network/network/", headers);
			JsonElement parsednetworkList = jsonparser.parse(networkList);
			
			for(JsonElement entry: parsednetworkList.getAsJsonArray()) {
				String networkUsedBy = sendGet(apibase + "/objects/network/network/" + entry.getAsJsonObject().get("_ref").getAsString() + "/usedby", headers);
				JsonElement parsedNetworkUsedBy = jsonparser.parse(networkUsedBy);
				
				if (parsedNetworkUsedBy.getAsJsonObject().get("objects").getAsJsonArray().size() == 0 && parsedNetworkUsedBy.getAsJsonObject().get("nodes").getAsJsonArray().size() == 0) {
					if (entry.getAsJsonObject().get("_locked").getAsString().isEmpty()) 
					{
						System.out.println("Empty and not locked: "  + entry.getAsJsonObject().get("name"));
						
						networkItemsToDelete.add(entry.getAsJsonObject().get("_ref").getAsString());
					}
				}
			}
			
			System.out.println("Detected " + networkItemsToDelete.size() + " unused items to delete. Continue?");
			reader.readLine();
			System.out.println("Are you really sure?");
			reader.readLine();
			
			HashMap<String, String> headersDelete = SerializationUtils.clone(headers);
			headersDelete.put("X-Restd-Err-Ack", "all");
			
			
			for (String s : networkItemsToDelete) 
			{
				sendDelete(apibase + "/objects/network/network/" + s, headersDelete);
			}
			
			System.out.println("Completed.");
			
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
		
	}
	
    static void close() throws IOException {
        httpClient.close();
    }

    static String sendGet(String url, HashMap<String, String> headers) throws Exception {

        HttpGet request = new HttpGet(url);

        // add request headers
        for(Entry<String, String> entry : headers.entrySet())
        {
        	request.addHeader(entry.getKey(), entry.getValue());
        }

        try (CloseableHttpResponse response = httpClient.execute(request)) {

            HttpEntity entity = response.getEntity();

            if (entity != null) {
                // return it as a String
            	return EntityUtils.toString(entity);
            }
            
            return null;

        }

    }

    static String sendDelete(String url, HashMap<String, String> headers) throws Exception {

    	HttpDelete delete = new HttpDelete(url);

        // add request headers
        for(Entry<String, String> entry : headers.entrySet())
        {
        	delete.addHeader(entry.getKey(), entry.getValue());
        }

        try (CloseableHttpResponse response = httpClient.execute(delete)) {

            HttpEntity entity = response.getEntity();

            if (entity != null) {
                // return it as a String
            	return EntityUtils.toString(entity);
            }
            
            return null;

        }
    }

}
