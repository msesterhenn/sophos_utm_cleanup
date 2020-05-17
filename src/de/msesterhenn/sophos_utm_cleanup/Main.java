package de.msesterhenn.sophos_utm_cleanup;

import java.io.BufferedReader;
import java.io.FileWriter;
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
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

public class Main {

	// one instance, reuse
	static CloseableHttpClient httpClient = null;

	static BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

	static Gson gson = new Gson();
	static JsonParser jsonparser = new JsonParser();

	public static void main(String[] args) {

		ArrayList<String> itemGroupsToCheck = new ArrayList<String>();

		itemGroupsToCheck.add("network/availability_group");
		itemGroupsToCheck.add("network/dns_group");
		itemGroupsToCheck.add("network/dns_host");
		itemGroupsToCheck.add("network/group");
		itemGroupsToCheck.add("network/host");
		itemGroupsToCheck.add("network/network");
		itemGroupsToCheck.add("network/range");
		itemGroupsToCheck.add("aaa/user");

		try {
			httpClient = HttpClients.custom()
					.setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
					.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();
		} catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e1) {
			e1.printStackTrace();
		}

		String apibase = "";
		String apikey = "";

		try {
			System.out.println("Enter UTM API Base (e.g. https://192.168.30.10:4444/api/) :");

			apibase = reader.readLine();

			System.out.println("Enter UTM API Key:");

			apikey = reader.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}

		try {
			FileWriter csvWriter = new FileWriter("deleted_items.csv");

			csvWriter.append("ItemGroup;ItemRef;ItemName;ItemValue\n");

			HashMap<String, List<String>> ItemsToDelete = new HashMap<String, List<String>>();

			HashMap<String, String> headers = new HashMap<String, String>();
			headers.put("Accept", "application/json");
			headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(("token:" + apikey).getBytes()));

			for (String itemGroup : itemGroupsToCheck) {

				ItemsToDelete.putIfAbsent(itemGroup, new ArrayList<String>());

				try {

					int itemcount = 0;

					String itemList = sendGet(apibase + "/objects/" + itemGroup + "/", headers);
					JsonElement parsedItemList = jsonparser.parse(itemList);

					for (JsonElement entry : parsedItemList.getAsJsonArray()) {
						String itemUsedBy = sendGet(apibase + "/objects/" + itemGroup + "/"
								+ entry.getAsJsonObject().get("_ref").getAsString() + "/usedby", headers);
						JsonElement parsedItemUsedBy = jsonparser.parse(itemUsedBy);

						if (parsedItemUsedBy.getAsJsonObject().get("objects").getAsJsonArray().size() == 0
								&& parsedItemUsedBy.getAsJsonObject().get("nodes").getAsJsonArray().size() == 0) {
							if (entry.getAsJsonObject().get("_locked").getAsString().isEmpty()) {
								System.out.println("Empty and not locked: " + entry.getAsJsonObject().get("name"));

								ItemsToDelete.get(itemGroup).add(entry.getAsJsonObject().get("_ref").getAsString());
								itemcount++;
								
							}
						}
					}

					System.out
							.println("Detected " + itemcount + " unused " + itemGroup + " items to delete. Continue? [n]");
					String input = reader.readLine();
					if (!input.equalsIgnoreCase("y"))
					{
						continue;
					}
					System.out.println("Are you really sure? [n]");
					String input2 = reader.readLine();
					if (!input2.equalsIgnoreCase("y"))
					{
						continue;
					}

					for (JsonElement entry : parsedItemList.getAsJsonArray()) 
					{
						if (ItemsToDelete.get(itemGroup).contains(entry.getAsJsonObject().get("_ref").getAsString())) {
							
							String itemValue = "";
							
							if (itemGroup.equals("network/availability_group")) 
							{
								StringBuilder sb = new StringBuilder();
								for (JsonElement e : entry.getAsJsonObject().get("members").getAsJsonArray())
								{
									sb.append(e.getAsString());
									sb.append(",");
								}
								
								itemValue = sb.toString();
								
							}
							else if (itemGroup.equals("network/dns_group"))
							{
								itemValue = entry.getAsJsonObject().get("hostname").getAsString();
							}
							else if (itemGroup.equals("network/dns_host"))
							{
								itemValue = entry.getAsJsonObject().get("hostname").getAsString();
							}
							else if (itemGroup.equals("network/group"))
							{
								StringBuilder sb = new StringBuilder();
								for (JsonElement e : entry.getAsJsonObject().get("members").getAsJsonArray())
								{
									sb.append(e.getAsString());
									sb.append(",");
								}
								
								itemValue = sb.toString();
							}
							else if (itemGroup.equals("network/host"))
							{
								itemValue = entry.getAsJsonObject().get("address").getAsString();
							}
							else if (itemGroup.equals("network/network"))
							{
								StringBuilder sb = new StringBuilder();
								sb.append(entry.getAsJsonObject().get("address").getAsString());
								sb.append("/" + entry.getAsJsonObject().get("netmask").getAsInt());
								
								itemValue = sb.toString();
							}
							else if (itemGroup.equals("network/range"))
							{
								StringBuilder sb = new StringBuilder();
								sb.append(entry.getAsJsonObject().get("from").getAsString());
								sb.append("-");
								sb.append(entry.getAsJsonObject().get("to").getAsString());
								
								itemValue = sb.toString();
							}
							else if (itemGroup.equals("aaa/user"))
							{
								StringBuilder sb = new StringBuilder();
								sb.append(entry.getAsJsonObject().get("name").getAsString());
								sb.append("-");
								sb.append(entry.getAsJsonObject().get("email_primary").getAsString());
								
								itemValue = sb.toString();
							}
							
							csvWriter.append(itemGroup + ";" + entry.getAsJsonObject().get("_ref").getAsString()  + ";" + entry.getAsJsonObject().get("name") + ";" + itemValue + "\n");
							
							
						}
					}
					
					csvWriter.flush();
					
					HashMap<String, String> headersDelete = SerializationUtils.clone(headers);
					headersDelete.put("X-Restd-Err-Ack", "all");

					for (String s : ItemsToDelete.get(itemGroup)) {
						sendDelete(apibase + "/objects/" + itemGroup + "/" + s, headersDelete);
					}

				} catch (Exception e) {
					e.printStackTrace();
				}

			}
			
			csvWriter.close();

		} catch (IOException e2) {
			e2.printStackTrace();
		}
		
		System.out.println("Completed.");

	}

	static void close() throws IOException {
		httpClient.close();
	}

	static String sendGet(String url, HashMap<String, String> headers) throws Exception {

		HttpGet request = new HttpGet(url);

		// add request headers
		for (Entry<String, String> entry : headers.entrySet()) {
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
		for (Entry<String, String> entry : headers.entrySet()) {
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
