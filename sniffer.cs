namespace Namespace {
    
    using socket;
    
    using sys;
    
    using @struct;
    
    using sys;
    
    using getopt;
    
    using array;
    
    using logging;
    
    using System.Collections.Generic;
    
    using System;
    
    public static class Module {
        
        static Module() {
            @"Funtion.
1, Unpack the packet by sniffer from kafka tcp port
2, Get the producer(client) ip, port and kafka protocol related info
3, Support multi partitions in one request for the topic.
4, Support tcp/ip packet fragmentation
5, limit: support kafka version < 0.11.0.1 right now, due to there is a big change on message format since kafka 0.11.0.1
";
            @"Usage.
1, Run on kafka broker server
2, python kafka_sniffer.py -t topicname -s 0.0.0.0 -p 9092
";
            @"
Author:Samuel
Date:20180218
";
            sniffer_info_log.setFormatter(fmt);
            sniffer_debug_log.setFormatter(fmt);
            info_logger.addHandler(sniffer_info_log);
            debug_logger.addHandler(sniffer_debug_log);
            main();
        }
        
        public static object kafka_data_output = new Dictionary<object, object> {
            {
                "SourceIP",
                null},
            {
                "SourcePort",
                -1},
            {
                "DestIP",
                null},
            {
                "DestPort",
                -1},
            {
                "DataLen",
                -1},
            {
                "ApiKey",
                -1},
            {
                "ApiVersion",
                -1},
            {
                "CorrelationId",
                -1},
            {
                "Client",
                null},
            {
                "RequiredAcks",
                -1},
            {
                "Timeout",
                -1},
            {
                "TopicCount",
                -1},
            {
                "TopicName",
                null},
            {
                "PartitionCount",
                -1},
            {
                "Partition",
                -1},
            {
                "MessageSetSize",
                -1},
            {
                "Offset",
                -1},
            {
                "MessageSize",
                -1},
            {
                "Crc",
                null},
            {
                "Magic",
                -1},
            {
                "Attribute",
                -1},
            {
                "Timestamp",
                -1},
            {
                "Key",
                null},
            {
                "Value",
                null}};
        
        public static object sniffer_info_log = logging.FileHandler(filename: "kafka-sniffer.data.log", mode: "w", encoding: "utf-8");
        
        public static object fmt = logging.Formatter(fmt: "%(asctime)s - %(name)s - %(levelname)s -%(module)s:  %(message)s", datefmt: "%Y-%m-%d %H:%M:%S");
        
        public static object sniffer_debug_log = logging.FileHandler(filename: "kafka-sniffer.debug.log", mode: "w", encoding: "utf-8");
        
        public static object fmt = logging.Formatter(fmt: "%(asctime)s - %(name)s - %(levelname)s -%(module)s:  %(message)s", datefmt: "%Y-%m-%d %H:%M:%S");
        
        public static object info_logger = logging.Logger(name: "kafka_data", level: logging.INFO);
        
        public static object debug_logger = logging.Logger(name: "kafka_debug", level: logging.INFO);
        
        public static object get_messageset_data(object data, object offset, object producer_data_len, object partition_loop) {
            var messageset_head = @struct.unpack(">I", data[offset::(offset  +  4)]);
            kafka_data_output["MessageSetSize"] = messageset_head[0];
            offset = offset + 4;
            offset = get_message_data(data, offset, producer_data_len, partition_loop);
            return offset;
        }
        
        public static object get_message_data(object data, object offset, object producer_data_len, object partition_loop) {
            var message_head = @struct.unpack(">QI", data[offset::(offset  +  12)]);
            kafka_data_output["Offset"] = message_head[0];
            kafka_data_output["MessageSize"] = message_head[1];
            offset = offset + 12;
            var message = @struct.unpack(">IBB", data[offset::(offset  +  6)]);
            kafka_data_output["Crc"] = message[0];
            kafka_data_output["Magic"] = Convert.ToInt32(message[1]);
            kafka_data_output["Attribute"] = Convert.ToInt32(message[2]);
            offset = offset + 6;
            //# kafka version >= 0.10
            if (kafka_data_output["Magic"] == 1) {
                kafka_data_output["Timestamp"] = @struct.unpack(">Q", data[offset::(offset  +  8)]);
                offset = offset + 8;
            }
            var key_len = @struct.unpack(">I", data[offset::(offset  +  4)]);
            offset = offset + 4;
            //# key is None,default 255,255,255,255
            if (key_len[0] == 4294967295) {
                kafka_data_output["Key"] = null;
            } else {
                kafka_data_output["Key"] = data[offset::(offset  +  key_len[0])];
                offset = offset + key_len[0];
            }
            var value_len = @struct.unpack(">I", data[offset::(offset  +  4)]);
            offset = offset + 4;
            kafka_data_output["Value"] = data[offset::(offset  +  value_len[0])];
            offset = offset + value_len[0];
            info_logger.info(kafka_data_output.items());
            if (partition_loop > 1) {
                return offset;
            }
            if (offset < producer_data_len) {
                get_message_data(data, offset, producer_data_len, partition_loop);
            } else {
                return offset;
            }
        }
        
        public static object get_topic_data(object data, object offset, object topic, object producer_data_len) {
            var topic_attribute = @struct.unpack(">IH", data[offset::(offset  +  6)]);
            kafka_data_output["TopicCount"] = topic_attribute[0];
            kafka_data_output["TopicLen"] = topic_attribute[1];
            offset = offset + 6;
            kafka_data_output["TopicName"] = data[offset::(offset  +  kafka_data_output["TopicLen"])];
            offset = offset + kafka_data_output["TopicLen"];
            if (kafka_data_output["TopicName"] == topic) {
                var partition_count = @struct.unpack(">I", data[offset::(offset  +  4)]);
                kafka_data_output["PartitionCount"] = partition_count[0];
                var partition_loop = partition_count[0];
                offset = offset + 4;
                while (offset < producer_data_len && partition_loop > 0) {
                    var partition = @struct.unpack(">I", data[offset::(offset  +  4)]);
                    info_logger.info(String.Format("======== From %s:%s, Topic %s, Partition Loop %s, Partition %s =======", kafka_data_output["SourceIP"], kafka_data_output["SourcePort"], kafka_data_output["TopicName"], partition_loop, partition[0]));
                    kafka_data_output["Partition"] = partition[0];
                    offset = offset + 4;
                    offset = get_messageset_data(data, offset, producer_data_len, partition_loop);
                    partition_loop = partition_loop - 1;
                }
                return;
            }
        }
        
        public static object get_producer_data(object data, object topic) {
            //# apikey + apiversion + correlationid + client
            var offset = 14;
            if (offset > data.Count) {
                return;
            }
            try {
                var client = @struct.unpack(">IHHIH", data[0::offset]);
                //# Producer ApiKey
                if (client[1] == 0) {
                    kafka_data_output["DataLen"] = client[0];
                    var producer_data_len = client[0];
                    kafka_data_output["ApiKey"] = client[1];
                    kafka_data_output["ApiVersion"] = client[2];
                    kafka_data_output["CorrelationId"] = client[3];
                    var client_len = client[4];
                    kafka_data_output["Client"] = data[offset::(offset  +  client_len)];
                    offset = offset + client_len;
                    //# if new protocol version
                    if (client[2] == 3) {
                        offset = offset + 2;
                    }
                    var client_attribute = @struct.unpack(">HI", data[offset::(offset  +  6)]);
                    kafka_data_output["RequiredAcks"] = client_attribute[0];
                    kafka_data_output["Timeout"] = client_attribute[1];
                    offset = offset + 6;
                    get_topic_data(data, offset, topic, producer_data_len);
                    return;
                }
            } catch (Exception) {
                debug_logger.debug(String.Format("The traffic from %s:%s struct.unpack failed.", kafka_data_output["SourceIP"], kafka_data_output["SourcePort"]));
                return;
            }
        }
        
        public static object unpack_tcpip_packet(object source, object port, object topic) {
            try {
                var s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP);
            } catch {
                debug_logger.debug(String.Format("Socket create failed. Error Code : %s Message %s ", msg[0].ToString(), msg[1]));
                sys.exit();
            }
            var data_buffer = bytes();
            //# tcp/ip conn pair
            var tcp_worker = new Dictionary<object, object> {
            };
            while (true) {
                var packet = s.recvfrom(65565);
                packet = packet[0];
                //# ip header
                var ip_header = packet[0::20];
                var iph = @struct.unpack("!BBHHHBBH4s4s", ip_header);
                //# tcp header
                var version_ihl = iph[0];
                var version = version_ihl >> 4;
                var ihl = version_ihl & 0xF;
                var iph_length = ihl * 4;
                var tcp_header = packet[iph_length::(iph_length  +  20)];
                var tcph = @struct.unpack("!HHLLBBHHH", tcp_header);
                var ttl = iph[5];
                var protocol = iph[6];
                var s_addr = socket.inet_ntoa(iph[8]);
                var d_addr = socket.inet_ntoa(iph[9]);
                //# tcp header
                tcp_header = packet[iph_length::(iph_length  +  20)];
                tcph = @struct.unpack("!HHLLBBHHH", tcp_header);
                var s_port = tcph[0];
                var d_port = tcph[1];
                var sequence = tcph[2];
                var acknowledgement = tcph[3];
                var doff_reserved = tcph[4];
                var tcph_length = doff_reserved >> 4;
                //# data
                var h_size = iph_length + tcph_length * 4;
                var data_size = packet.Count - h_size;
                var data = packet[h_size];
                kafka_data_output["SourceIP"] = s_addr;
                kafka_data_output["SourcePort"] = s_port;
                kafka_data_output["DestIP"] = d_addr;
                kafka_data_output["DestPort"] = d_port;
                var key = s_addr + "," + s_port.ToString() + "," + d_addr + "," + d_port.ToString();
                //# solve ip/tcp fragmentation
                var first_packet = false;
                if (!tcp_worker.Contains(key)) {
                    first_packet = true;
                    tcp_worker[key] = data;
                } else {
                    tcp_worker[key] = tcp_worker[key] + data;
                }
                //# parse head of data
                while (true) {
                    if (tcp_worker[key].Count < 14) {
                        debug_logger.debug(String.Format("The traffic from %s:%s is too short(len:%s) to analyze.", s_addr, s_port, tcp_worker[key].Count));
                        tcp_worker.pop(key, null);
                        break;
                    }
                    try {
                        var client = @struct.unpack(">IHHIH", tcp_worker[key][0::14]);
                    } catch (Exception) {
                        //# first packet can not be unpacked
                        if (first_packet) {
                            tcp_worker.pop(key, null);
                        }
                        debug_logger.debug(String.Format("The packet from %s:%s is fragmentation, or upack failed", s_addr, s_port));
                        break;
                    }
                    var kafka_data_size = client[0];
                    if (tcp_worker[key].Count < 4 + kafka_data_size) {
                        if (first_packet) {
                            tcp_worker.pop(key, null);
                        }
                        debug_logger.debug(String.Format("The packet from %s:%s is fragmentation, or upack failed", s_addr, s_port));
                        break;
                    }
                    if (source == "0.0.0.0") {
                        get_producer_data(tcp_worker[key], topic);
                        tcp_worker[key] = tcp_worker[key][4 + kafka_data_size];
                    } else if (source == s_addr) {
                        get_producer_data(tcp_worker[key], topic);
                        tcp_worker[key] = tcp_worker[key][4 + kafka_data_size];
                    } else {
                        break;
                    }
                }
                //# tcp/ip conn pair is None
                if (tcp_worker.Contains(key) && tcp_worker[key].Count == 0) {
                    debug_logger.debug(String.Format("Remove tcp/ip conn pair %s from tcp_worker", key));
                    tcp_worker.pop(key, null);
                }
            }
        }
        
        public static object main() {
            try {
                var _tup_1 = getopt.getopt(sys.argv[1], "-ht:s:p:", new List<object> {
                    "h",
                    "t",
                    "s",
                    "p"
                });
                var opts = _tup_1.Item1;
                var args = _tup_1.Item2;
            } catch {
                Console.WriteLine("Error: kafka_sniffer.py -t <topic> -s <source> -p <kafka_port>");
                sys.exit(2);
            }
            if (opts.Count == 0) {
                Console.WriteLine("Error: python kafka_sniffer.py -h for help");
                sys.exit(2);
            }
            foreach (var _tup_2 in opts) {
                var opt = _tup_2.Item1;
                var arg = _tup_2.Item2;
                if (opt == "-h") {
                    Console.WriteLine(" kafka_sniffer.py -t <topic> -s <source> -p <kafka_port>");
                    Console.WriteLine(" if all topics, topic=all");
                    Console.WriteLine(" if all sources, source=0.0.0.0");
                    sys.exit();
                }
                if ("-t".Contains(opt)) {
                    var topic = arg;
                }
                if ("-s".Contains(opt)) {
                    var source = arg;
                }
                if ("-p".Contains(opt)) {
                    var port = arg;
                }
            }
            Console.WriteLine("Input: ");
            Console.WriteLine("Topic: " + topic);
            Console.WriteLine("Source: " + source);
            Console.WriteLine("Port: " + port);
            unpack_tcpip_packet(source, port, topic);
        }
    }
}
