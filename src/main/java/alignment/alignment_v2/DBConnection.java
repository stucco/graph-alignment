package alignment.alignment_v2;

import java.io.IOException;

import org.apache.commons.configuration.BaseConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.thinkaurelius.titan.core.TitanGraph;
import com.tinkerpop.rexster.client.RexsterClient;
import com.tinkerpop.rexster.client.RexsterClientFactory;
import com.tinkerpop.rexster.client.RexsterClientTokens;
import com.tinkerpop.rexster.protocol.serializer.msgpack.MsgPackSerializer;

public class DBConnection {
	
    public static RexsterClient getDefaultClient(){
    	RexsterClient client = null;
    	
    	//TODO: these timeouts seem to do nothing.  If the server is down, it seems to wait (& apparently retry) forever.
    	// should probably submit a bug report for this.
        BaseConfiguration configOpts = new BaseConfiguration() {{
            addProperty(RexsterClientTokens.CONFIG_HOSTNAME, "localhost");
            addProperty(RexsterClientTokens.CONFIG_PORT, 8184);
            addProperty(RexsterClientTokens.CONFIG_TIMEOUT_CONNECTION_MS, 18000);
            addProperty(RexsterClientTokens.CONFIG_TIMEOUT_WRITE_MS, 4000);
            addProperty(RexsterClientTokens.CONFIG_TIMEOUT_READ_MS, 16000);
            addProperty(RexsterClientTokens.CONFIG_MAX_ASYNC_WRITE_QUEUE_BYTES, 512000);
            addProperty(RexsterClientTokens.CONFIG_MESSAGE_RETRY_COUNT, 4);
            addProperty(RexsterClientTokens.CONFIG_MESSAGE_RETRY_WAIT_MS, 50);
            addProperty(RexsterClientTokens.CONFIG_LANGUAGE, "groovy");
            addProperty(RexsterClientTokens.CONFIG_GRAPH_OBJECT_NAME, "g");
            addProperty(RexsterClientTokens.CONFIG_GRAPH_NAME, "graph"); //not rename-able?  Seems like a Titan thing?
            addProperty(RexsterClientTokens.CONFIG_TRANSACTION, true);
            addProperty(RexsterClientTokens.CONFIG_SERIALIZER, MsgPackSerializer.SERIALIZER_ID);
        }};
        Logger logger = LoggerFactory.getLogger(Align.class);
        logger.info("connecting to DB...");
		try {
			client = RexsterClientFactory.open(configOpts); //this just throws "Exception."  bummer.
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
//		System.out.println("client" + client);
    	return client;
    }
    
    public static RexsterClient getTestClient(){
    	RexsterClient client = null;
    	TitanGraph g = null;
    	Logger logger = LoggerFactory.getLogger(Align.class);
        
    	BaseConfiguration configOpts = new BaseConfiguration() {{
    		addProperty(RexsterClientTokens.CONFIG_MESSAGE_RETRY_COUNT, 1);
    		addProperty(RexsterClientTokens.CONFIG_PORT, 7184);
            addProperty(RexsterClientTokens.CONFIG_GRAPH_OBJECT_NAME, "g");
            addProperty(RexsterClientTokens.CONFIG_GRAPH_NAME, "graph"); //not rename-able?  Seems like a Titan thing?
            addProperty(RexsterClientTokens.CONFIG_TRANSACTION, true);
            addProperty(RexsterClientTokens.CONFIG_SERIALIZER, MsgPackSerializer.SERIALIZER_ID);
        }};
    	
        logger.info("connecting to Test DB...");
        try{
        	client = RexsterClientFactory.open(configOpts);		//this just throws "Exception."  bummer.
        }catch(Exception e){
        	//don't care.
        }
		
    	return client;
    }
	
	public static void closeClient(RexsterClient client){
		if(client != null){
			try {
				client.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			client = null;
		}
    }
}
