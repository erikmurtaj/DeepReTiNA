package cic.cs.unb.ca.jnetpcap;

import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import static cic.cs.unb.ca.jnetpcap.Utils.LINE_SEP;


public class FlowGenerator {
    public static final Logger logger = LoggerFactory.getLogger(FlowGenerator.class);

    //total 85 colums
	/*public static final String timeBasedHeader = "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, "
			+ "Timestamp, Flow Duration, Total Fwd Packets, Total Backward Packets,"
			+ "Total Length of Fwd Packets, Total Length of Bwd Packets, "
			+ "Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std,"
			+ "Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std,"
			+ "Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,"
			+ "Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,"
			+ "Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,"
			+ "Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length,"
			+ "Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance,"
			+ "FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, "
			+ "CWR Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length,"
			+ "Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk,"
			+ "Bwd Avg Bulk Rate,"
			+ "Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes,"
			+ "Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward,"
			+ "Active Mean, Active Std, Active Max, Active Min,"
			+ "Idle Mean, Idle Std, Idle Max, Idle Min, Label";*/

	//40/86
	private FlowGenListener mListener;
	private HashMap<String,BasicFlow> currentFlows;
	private HashMap<Integer,BasicFlow> finishedFlows;
	private HashMap<String,ArrayList> IPAddresses;

	private boolean bidirectional;
	private long    flowTimeOut;
	private long    flowActivityTimeOut;
	private int     finishedFlowCount;
	
	public FlowGenerator(boolean bidirectional, long flowTimeout, long activityTimeout) {
		super();
		this.bidirectional = bidirectional;
		this.flowTimeOut = flowTimeout;
		this.flowActivityTimeOut = activityTimeout; 
		init();
	}		
	
	private void init(){
		currentFlows = new HashMap<>();
		finishedFlows = new HashMap<>();
		IPAddresses = new HashMap<>();
		finishedFlowCount = 0;		
	}

	public void addFlowListener(FlowGenListener listener) {
		mListener = listener;
	}

    public void addPacket(BasicPacketInfo packet){
        if(packet == null) {
            return;
        }
        
    	BasicFlow   flow;
    	long        currentTimestamp = packet.getTimeStamp();
		    String id;

    	if(this.currentFlows.containsKey(packet.fwdFlowId())||this.currentFlows.containsKey(packet.bwdFlowId())){
	
	if(this.currentFlows.containsKey(packet.fwdFlowId())) 
		{id = packet.fwdFlowId();}
    		else {
		id = packet.bwdFlowId();}

    		flow = currentFlows.get(id);
    		// Flow finished due flowtimeout: 
    		// 1.- we move the flow to finished flow list
    		// 2.- we eliminate the flow from the current flow list
    		// 3.- we create a new flow with the packet-in-process
    		if((currentTimestamp -flow.getFlowStartTime())>flowTimeOut){
    			if(flow.packetCount()>1){
					if (mListener != null) {
						mListener.onFlowGenerated(flow);
					    }
					else{
                                                finishedFlows.put(getFlowCount(), flow);
                                            }
                    //flow.endActiveIdleTime(currentTimestamp,this.flowActivityTimeOut, this.flowTimeOut, false);
    			}
    			currentFlows.remove(id);    			
				currentFlows.put(id, new BasicFlow(bidirectional,packet,flow.getSrc(),flow.getDst(),flow.getSrcPort(),flow.getDstPort(), this.flowActivityTimeOut));
    			
    			int cfsize = currentFlows.size();
    			if(cfsize%50==0) {
    				logger.debug("Timeout current has {} flow",cfsize);
    	    	}
    			
//        	// Flow finished due FIN flag (tcp only):
//    		// 1.- we add the packet-in-process to the flow (it is the last packet)
//        	// 2.- we move the flow to finished flow list
//        	// 3.- we eliminate the flow from the current flow list   	
//    		}else if(packet.hasFlagFIN()){
//    	    	logger.debug("FlagFIN current has {} flow",currentFlows.size());
//    	    	flow.addPacket(packet);
//                if (mListener != null) {
//                    mListener.onFlowGenerated(flow);
//                } else {
//                    finishedFlows.put(getFlowCount(), flow);
//                }
//                currentFlows.remove(id);
    		}else if(packet.hasFlagFIN()){
    			//
    			// Forward Flow
    			//
    			if (Arrays.equals(flow.getSrc(), packet.getSrc())) {
    				// How many forward FIN received? 
    				if (flow.setFwdFINFlags() == 1) {
    		        	// Flow finished due FIN flag (tcp only)?:
    		    		// 1.- we add the packet-in-process to the flow (it is the last packet)
    		        	// 2.- we move the flow to finished flow list
    		        	// 3.- we eliminate the flow from the current flow list       					
    					if ((flow.getBwdFINFlags() + flow.getBwdFINFlags()) == 2) {
    		    	    	logger.debug("FlagFIN current has {} flow",currentFlows.size());
    		    	    	flow.addPacket(packet);
    		                if (mListener != null) {
    		                    mListener.onFlowGenerated(flow);
    		                } else {
    		                    finishedFlows.put(getFlowCount(), flow);
    		                }
    		                currentFlows.remove(id);
    		            // Forward Flow Finished.
    					} else {
    						logger.info("Forward flow closed due to FIN Flag");
    		    			flow.updateActiveIdleTime(currentTimestamp,this.flowActivityTimeOut);
    		    			flow.addPacket(packet);
    		    			currentFlows.put(id,flow);    						
    					}
    				}else{
    					// some error
    					// TODO: review what to do with the packet
    					logger.warn("Forward flow received {} FIN packets", flow.getFwdFINFlags());
    				}
    		    //
    			// Backward Flow
    		    //
    			} else {    				
    				// How many backward FIN packets received?
    				if (flow.setBwdFINFlags() == 1) {
    		        	// Flow finished due FIN flag (tcp only)?:
    		    		// 1.- we add the packet-in-process to the flow (it is the last packet)
    		        	// 2.- we move the flow to finished flow list
    		        	// 3.- we eliminate the flow from the current flow list       					
    					if ((flow.getBwdFINFlags() + flow.getBwdFINFlags()) == 2) {
    		    	    	logger.debug("FlagFIN current has {} flow",currentFlows.size());
    		    	    	flow.addPacket(packet);
    		                if (mListener != null) {
    		                    mListener.onFlowGenerated(flow);
    		                } else {
    		                    finishedFlows.put(getFlowCount(), flow);
    		                }
    		                currentFlows.remove(id);
    		            // Backward Flow Finished.
    					} else {
    						logger.info("Backwards flow closed due to FIN Flag");
    		    			flow.updateActiveIdleTime(currentTimestamp,this.flowActivityTimeOut);
    		    			flow.addPacket(packet);
    		    			currentFlows.put(id,flow);    						
    					}
    				}else{
    					// some error
    					// TODO: review what to do with the packet
    					logger.warn("Backward flow received {} FIN packets", flow.getBwdFINFlags());    					
    				}    				
    			}
        	// Flow finished due RST flag (tcp only):
    		// 1.- we add the packet-in-process to the flow (it is the last packet)
        	// 2.- we move the flow to finished flow list
        	// 3.- we eliminate the flow from the current flow list                
    		}else if(packet.hasFlagRST()){
    			logger.debug("FlagRST current has {} flow",currentFlows.size());
    			flow.addPacket(packet);
                if (mListener != null) {
                    mListener.onFlowGenerated(flow);
                } else {
                    finishedFlows.put(getFlowCount(), flow);
                }
                currentFlows.remove(id);    			
    		}else{
    			//
    			// Forward Flow and fwdFIN = 0
    			//
    			if (Arrays.equals(flow.getSrc(), packet.getSrc()) && (flow.getFwdFINFlags() == 0)) {
        			flow.updateActiveIdleTime(currentTimestamp,this.flowActivityTimeOut);
        			flow.addPacket(packet);
        			currentFlows.put(id,flow);
    			// 
    			// Backward Flow and bwdFIN = 0
    			//    				
    			} else if (flow.getBwdFINFlags() == 0) {
        			flow.updateActiveIdleTime(currentTimestamp,this.flowActivityTimeOut);
        			flow.addPacket(packet);
        			currentFlows.put(id,flow);
        		//
        		// FLOW already closed!!!
        		//
    			} else {
    				logger.warn("FLOW already closed! fwdFIN {} bwdFIN {}", flow.getFwdFINFlags(), flow.getBwdFINFlags());
    				// TODO: we just discard the packet?
    			}
    		}
    	}else{
			currentFlows.put(packet.fwdFlowId(), new BasicFlow(bidirectional,packet, this.flowActivityTimeOut));
    	}
    }

    /*public void dumpFlowBasedFeatures(String path, String filename,String header){
    	BasicFlow   flow;
    	try {
    		System.out.println("TOTAL Flows: "+(finishedFlows.size()+currentFlows.size()));
    		FileOutputStream output = new FileOutputStream(new File(path+filename));    
    		
    		output.write((header+"\n").getBytes());
    		Set<Integer> fkeys = finishedFlows.keySet();    		
			for(Integer key:fkeys){
	    		flow = finishedFlows.get(key);
	    		if(flow.packetCount()>1)				
	    			output.write((flow.dumpFlowBasedFeaturesEx()+"\n").getBytes());
			}
			Set<String> ckeys = currentFlows.keySet();   		
			for(String key:ckeys){
	    		flow = currentFlows.get(key);
	    		if(flow.packetCount()>1)				
	    			output.write((flow.dumpFlowBasedFeaturesEx()+"\n").getBytes());
			}			
			
			output.flush();
			output.close();			
		} catch (IOException e) {
			e.printStackTrace();
		}

    }*/

    public int dumpLabeledFlowBasedFeatures(String path, String filename,String header){
    	BasicFlow   flow;
    	int         total = 0;
    	int   zeroPkt = 0;

    	try {
    		//total = finishedFlows.size()+currentFlows.size(); becasue there are 0 packet BasicFlow in the currentFlows

    		FileOutputStream output = new FileOutputStream(new File(path+filename));
			logger.debug("dumpLabeledFlow: ", path + filename);
    		output.write((header+"\n").getBytes());
    		Set<Integer> fkeys = finishedFlows.keySet();    		
			for(Integer key:fkeys){
	    		flow = finishedFlows.get(key);
                         if (flow.packetCount() > 1) {
                           output.write((flow.dumpFlowBasedFeaturesEx() + "\n").getBytes());
                           total++;
                           } 
                         else {
                           zeroPkt++;
                         }
                }
            logger.debug("dumpLabeledFlow finishedFlows -> {},{}",zeroPkt,total);

            Set<String> ckeys = currentFlows.keySet();
		output.write((header + "\n").getBytes());
			for(String key:ckeys){
	    		flow = currentFlows.get(key);
	    		if(flow.packetCount()>1) {
                    output.write((flow.dumpFlowBasedFeaturesEx() + "\n").getBytes());
                    total++;
                }else{
                    zeroPkt++;
                }

			}
            logger.debug("dumpLabeledFlow total(include current) -> {},{}",zeroPkt,total);
            output.flush();
            output.close();
        } catch (IOException e) {

            logger.debug(e.getMessage());
        }

        return total;
    }       

    public long dumpLabeledCurrentFlow(String fileFullPath,String header) {
        if (fileFullPath == null || header==null) {
            String ex = String.format("fullFilePath=%s,filename=%s", fileFullPath);
            throw new IllegalArgumentException(ex);
        }

        File file = new File(fileFullPath);
        FileOutputStream output = null;
        int total = 0;
        try {
            if (file.exists()) {
                output = new FileOutputStream(file, true);
            }else{
                if (file.createNewFile()) {
                    output = new FileOutputStream(file);
                    output.write((header + LINE_SEP).getBytes());
                }
            }

            for (BasicFlow flow : currentFlows.values()) {
                if(flow.packetCount()>1) {
                    output.write((flow.dumpFlowBasedFeaturesEx() + LINE_SEP).getBytes());
                    total++;
                }else{

                }
            }

        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    output.close();
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
        return total;
	}

    private int getFlowCount(){
    	this.finishedFlowCount++;
    	return this.finishedFlowCount;
    }
}
