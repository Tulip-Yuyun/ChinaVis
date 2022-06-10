import csv
import json
import random
import pickle
from flask import Flask

app = Flask(__name__)


def read_node_and_link():
    """
    读取文件, 转换成对应的数据结构
    """
    nodes = {}
    links = {}

    csv_reader_node = csv.reader(open("./data/Node.csv", encoding="utf-8"))
    csv_reader_link = csv.reader(open("./data/Link.csv", encoding="utf-8"))
    next(csv_reader_node)
    next(csv_reader_link)

    # read link
    for line in csv_reader_link:
        relation = line[0]
        source = line[1]
        target = line[2]
        # 存储双向边
        if target in links:
            links[target] += [(source, relation + "_reverse")]
        elif target not in links:
            links[target] = [(source, relation + "_reverse")]
        if source in links:
            links[source] += [(target, relation)]
        elif source not in links:
            links[source] = [(target, relation)]

    # read node
    for line in csv_reader_node:
        id = line[0]
        name = line[1]
        type = line[2]
        industry = eval(line[3])
        node = {"name": name, "type": type, "industry": industry}
        nodes[id] = node

    return nodes, links


def adjacency_list(triple):
    """
    三元组转换为邻接表的图结构
    """
    graph = {}
    for tri in triple:
        source = tri[0]
        target = tri[1]
        relation = tri[2]
        if source in graph:
            graph[source] += [(target, relation)]
        else:
            graph[source] = [(target, relation)]
        if target in graph:
            graph[target] += [(source, relation + "_reverse")]
        else:
            graph[target] = [(source, relation + "_reverse")]
    return graph


def get_relation_hop(relation):
    """
    返回不同类型的结点应该展开几跳, 这些可以根据需求去改
    """
    hop = {
        "r_cert": 3,
        "r_subdomain": 3,
        "r_request_jump": 3,
        "r_dns_a": 3,
        "r_whois_name": 2,
        "r_whois_email": 2,
        "r_whois_phone": 2,
        "r_cert_chain": 1,
        "r_cname": 1,
        "r_asn": 0,
        "r_cidr": 0
    }
    if "_reverse" in relation:
        relation = relation[:-8]
    return hop[relation]


def bfs_connect(links, source, destination, k=5):
    """
    k跳之内两个node是否能够有可达的边（判断两点是否有边可达）
    """
    vis = set()
    # source
    queue = [(source, k)]
    vis.add(source)
    # bfs
    while len(queue) != 0:
        id, jump = queue.pop(0)
        if id in links:
            for neighbour in links[id]:
                if neighbour == destination:
                    return True
                else:
                    if jump > 0 and neighbour[0] not in vis:
                        queue += [(neighbour[0], jump - 1)]
                        vis.add(neighbour[0])
    return False


def get_one_way_links(links, source):
    """
    获取source的邻接点, 如果没有从source出去的点, 才会考虑双向边
    not use
    """
    link = links[source]
    link = sorted(link, key=lambda x: x[1])
    if len(link) > 0 and "_reverse" in link[0][1]:
        return link
    else:
        # 除去_reverse
        new_link = []
        for l in link:
            if "_reverse" in l[1]:
                break
            new_link += [l]
        return new_link


def bfs(nodes, links, source_id_list, hop_extra_limitation=False, k=3):
    """
    bfs 找到k跳以内的三元组, 并考虑展开的跳数
    """
    visit = set()
    queue = []
    for source_id in source_id_list:
        queue += [(source_id, k)]
        visit.add(source_id)
    triple = []
    while len(queue) != 0:
        id, jump = queue.pop(0)
        if id in links:
            for neighbour, relation in filter_link(nodes, links, visit, id,
                                                   links[id]):  # 得到一个list，里面是target 和 relation的二元组
                if hop_extra_limitation:
                    jump = min(jump, get_relation_hop(relation))  # jump 当前该结点展开的跳数
                if jump > 0 and neighbour not in visit:
                    queue += [(neighbour, jump - 1)]  # 跳了一步后，剩余可以跳的步数-1，深度+1，继续放到点展开的queue中
                    visit.add(neighbour)
                # 添加三元组
                if "_reverse" in relation:
                    triple += [(neighbour, id, relation[:-8])]
                else:
                    triple += [(id, neighbour, relation)]
    return triple


def get_similar_node(nodes, graph):
    """
    预处理相似的结点, 若node类型和neighbour一样, 则认为相似
    graph中的边应该只考虑单项边
    not use
    """
    # 得到graph中所有结点
    graph_nodes = set()
    for source in graph:
        graph_nodes.add(source)
        for neighbour, _ in graph[source]:
            graph_nodes.add(neighbour)
    # key是(neighbour的hash, type), value是node数组
    dict = {}
    for node_id in graph_nodes:  # 因为是双向边, 所以只需要遍历key就行了
        if node_id not in graph:
            continue
        neighbour_hash = hash(str(graph[node_id]))
        node_type = nodes[node_id]["type"]
        if (neighbour_hash, node_type) not in dict:
            dict[(neighbour_hash, node_type)] = [node_id]
        else:
            dict[(neighbour_hash, node_type)] += [node_id]
    return dict


def bfs_combine(nodes, graph, source_id_list):
    """
    压缩, 如果n个结点邻接点一样, type一样, relation也一样, 则认为他们都是一个结点, 并统计个数
    not use
    """
    visit = set()
    queue = []
    for source_id in source_id_list:
        queue += [source_id]
        visit.add(source_id)
    triple = {}  # (source, target_hash, target_type, relation): [count, target]
    while len(queue) != 0:
        source = queue.pop(0)
        if source in graph:
            for target, relation in graph[source]:
                if target not in visit:
                    target_hash = hash(str(graph[target]))
                    target_type = nodes[target]["type"]
                    visit.add(target)
                    if (source, target_hash, target_type, relation) in triple:
                        triple[(source, target_hash, target_type, relation)][1] += 1
                    else:
                        queue += [target]
                        triple[(source, target_hash, target_type, relation)] = [target, 1]
    # 转换成原来三元组的结构
    new_triple = []
    for key in triple:
        source, _, _, relation = key
        if "_reverse" in relation:
            new_triple += [[triple[key][0], source, relation, triple[key][1]]]
        else:
            new_triple += [[source, triple[key][0], relation, triple[key][1]]]
    return new_triple


def statistic(nodes, triple, has_count=False):
    """
    统计triple中不同类型node的个数
    """
    node_sum = {}
    node_set = set()
    max_count = 0
    for tri in triple:
        source_id = tri[0]
        target_id = tri[1]
        if has_count:
            max_count = max(max_count, tri[3])
        source_type = nodes[source_id]["type"]
        target_type = nodes[target_id]["type"]
        if source_id not in node_set:
            node_set.add(source_id)
            if source_type not in node_sum:
                node_sum[source_type] = 1
            else:
                node_sum[source_type] += 1
        if target_id not in node_set:
            node_set.add(target_id)
            if target_type not in node_sum:
                node_sum[target_type] = 1
            else:
                node_sum[target_type] += 1
    for i in node_sum:
        print(f"type:{i},count:{node_sum[i]}")
    print(f"link_num:{len(triple)}")
    if has_count:
        print(f"max_count: {max_count}")


def analysis(nodes, graph):
    """
    分析搜出来的子图, 如结点邻接点的个数与结点type的关系等
    来指导进一步处理
    """
    print("------类型相同且邻接点个数相同的结点个数------")
    result = {}  # {(type, 邻接点个数): count}
    for node in graph:
        link_size = len(graph[node])
        node_type = nodes[node]["type"]
        if (node_type, link_size) in result:
            result[(node_type, link_size)] += 1
        else:
            result[(node_type, link_size)] = 1
    for r in sorted(result):
        node_type, link_size = r
        print(f"{node_type}, {link_size}: {result[r]}")
    print("------结点的邻接点类型相同的结点个数------")
    result = {}  # {(type, domain_cnt, xxx_cnt, ...): count}
    for node in graph:
        node_cnt = {
            "Domain": 0,
            "IP": 0,
            "Cert": 0,
            "Whois_Name": 0,
            "Whois_Phone": 0,
            "Whois_Email": 0,
            "IP_C": 0,
            "ASN": 0
        }
        for target, relation in graph[node]:
            target_type = nodes[target]["type"]
            node_cnt[target_type] += 1
        node_type = nodes[node]["type"]
        key = (node_type,)
        for t in node_cnt:
            key += (node_cnt[t],)
        if key in result:
            result[key] += 1
        else:
            result[key] = 1
    for r in sorted(result):
        # print(f"({r[0]}, Domain:{r[1]}, IP:{r[2]}, Cert:{r[3]}, Name:{r[4]}, Phone:{r[5]}, Email:{r[6]},"
        #       f"IP_C:{r[7]}, ASN:{r[8]}): {result[r]}")
        print(f"{r}: {result[r]}")


def category2svg(category):
    """
    返回node对应类别的svg图标
    """
    dic = {
        "Domain": "image://./icon/Domain.svg",
        "Whois_Name": "image://./icon/Whois_Name.svg",
        "Whois_Email": "image://./icon/Whois_Email.svg",
        "Whois_Phone": "image://./icon/Whois_Phone.svg",
        "IP": "image://./icon/IP.svg",
        "Cert": "image://./icon/Cert.svg",
        "ASN": "image://./icon/ASN.svg",
        "IP_C": "image://./icon/IP_C.svg",
    }
    return dic[category]


def get_node_type(node_type):
    """
    把type转换为index
    """
    type_dict = get_type_map()
    return type_dict[node_type]


def get_type_map():
    return {
        "Domain": 0,
        "Whois_Name": 1,
        "Whois_Email": 2,
        "Whois_Phone": 3,
        "IP": 4,
        "Cert": 5,
        "ASN": 6,
        "IP_C": 7,
    }


def process_echart(nodes, triple, start_nodes=None):
    """
    根据三元组, 转换成echart数据格式
    """
    if start_nodes is None:
        start_nodes = set()
    link_echart = []  # 存储echart的link信息
    node_set = set()
    node_echart = []
    for tri in triple:
        source = tri[0]
        target = tri[1]
        relation = tri[2]
        link_echart += [{"source": source, "target": target, "value": relation}]
        if source not in node_set:
            if source in start_nodes:
                node_echart += [{"id": source, "category": get_node_type(nodes[source]["type"]),
                                 "symbolSize": 12, "name": source, "expand": False, "start": True}]
            else:
                node_echart += [{"id": source, "category": get_node_type(nodes[source]["type"]),
                                 "symbolSize": 12, "name": source, "expand": False, "start": False}]
            node_set.add(source)
        if target not in node_set:
            if target in start_nodes:
                node_echart += [{"id": target, "category": get_node_type(nodes[target]["type"]),
                                 "symbolSize": 12, "name": target, "expand": False, "start": True}]
            else:
                node_echart += [{"id": target, "category": get_node_type(nodes[target]["type"]),
                                 "symbolSize": 12, "name": target, "expand": False, "start": False}]
            node_set.add(target)

    # echart category
    category_echart = []
    categories = get_type_map()
    for category in categories:
        category_echart += [{"name": category}]
    echart = {"nodes": node_echart, "links": link_echart, "categories": category_echart}

    return echart


def filter_link(nodes, links, node_set, expand_node, node_links):
    """
    node_set :当前知识图谱图中展开的点 expand_node :当前要展开的点，鼠标点击的
    过滤邻接点, 根据邻接点的类型, neighbour进行排序, 取topk
    统计数据:
    ASN:只会和IP产生关系(IP的自治域), 且和10个以下的IP产生联系的数量为155, 和10~99个IP产生联系的数量为19, 100~111个IP产生联系的为107,
        其余都是>112, 大约75个, 所以不展开
    Cert:和Cert的关系, 从统计数据看, 和1个Cert产生的关联较多(几乎占90%), 所以有Cert尽量展开Cert, 上限为2
        和Domain的关系, 和<=10个Domain产生的关联较多, 上限为10
    Domain: Domain的关系比较杂, 上限在(20,5,5,5,5,5,1,2), 可以改, 言之成理即可
    IP:会关联到Domain,IP_C以及ASN, Domain个数大多在200个一下, IP_C个数在0~1(有一个IP有2), ASN范围在0~3
        所以Domain上限为20, IP_C上限为1, ASN上限为2
    IP_C:只会关联到IP, 大多在106以下, 上限为20
    name/phone/email:只会关联到Domain, 上限20

    筛选策略(比如有100个点, 怎么保留20个)：
    根据这些点的属性排序, 会考虑expand_node和这些点的relation, 以及这个点自身的neighbour, 以及neighbour与当前展开图的关系
    按照是否和当前图有关系为第一关键字, relation为第二关键字, neighour个数的大小为第三关键字排序
    """
    # 每种类型展开的上限, 这些可以根据需求去改
    expand_limitation = {
        "Domain": (20, 5, 5, 5, 5, 5, 1, 2),
        "IP": (20, 0, 0, 0, 0, 0, 1, 2),
        "Cert": (10, 0, 2, 0, 0, 0, 0, 0),
        "Whois_Name": (20, 0, 0, 0, 0, 0, 0, 0),
        "Whois_Phone": (20, 0, 0, 0, 0, 0, 0, 0),
        "Whois_Email": (20, 0, 0, 0, 0, 0, 0, 0),
        "IP_C": (0, 20, 0, 0, 0, 0, 0, 0),
        "ASN": (0, 0, 0, 0, 0, 0, 0, 0)
    }
    limitation = expand_limitation[nodes[expand_node]["type"]]
    # 统计一下邻接点的类型
    node_cnt = {
        "Domain": 0,
        "IP": 0,
        "Cert": 0,
        "Whois_Name": 0,
        "Whois_Phone": 0,
        "Whois_Email": 0,
        "IP_C": 0,
        "ASN": 0
    }
    target_by_type = {
        "Domain": [],
        "IP": [],
        "Cert": [],
        "Whois_Name": [],
        "Whois_Phone": [],
        "Whois_Email": [],
        "IP_C": [],
        "ASN": []
    }
    for target, relation in node_links:
        target_type = nodes[target]["type"]
        node_cnt[target_type] += 1
        if target in links:
            target_by_type[target_type] += [
                (target, relation, target in node_set, get_relation_hop(relation), len(links[target]))]
        else:
            target_by_type[target_type] += [(target, relation, target in node_set, get_relation_hop(relation), 0)]
    # print(f"邻接点类型: {node_cnt}")
    # filter, 处理每种类型的结点
    result = []
    i = 0
    for t in target_by_type:
        target_nodes = target_by_type[t]
        type_limitation = limitation[i]
        if len(target_nodes) < type_limitation:
            result += target_nodes
        else:
            target_nodes = sorted(target_nodes, key=lambda x: (x[2], x[3], x[4]), reverse=True)
            result += target_nodes[:type_limitation]
        i += 1
    result = [(x[0], x[1]) for x in result]
    return result


def get_adjacency(graph):
    links = graph['links']
    nodes = graph['nodes']

    res = {}
    for link in links:
        source = link['source']
        target = link['target']
        rel = link['value']

        if source in res.keys():
            res[source].append({"target": target, "rel": rel, "category": nodes[target]['category']})
        else:
            res[source] = [{"target": target, "rel": rel, "category": nodes[target]['category']}]
    with open("data/tmp.json", 'w', encoding='utf-8') as f:
        f.write(json.dumps(res, indent=4))
    return res


def get_core(graph, adjacency):
    nodes = graph['nodes']
    categories = graph['categories']

    core_nodes = []
    # 50% 以上的边为强度较弱的不是核心资产
    for source, targets in adjacency.items():
        link_num = len(targets)
        weak_link_num = 0
        for target in targets:
            if target['rel'] == 'r_asn' or target['rel'] == 'r_cidr':
                weak_link_num += 1
        if weak_link_num / link_num <= 0.5:
            core_nodes.append(source)

    # 关联 2 个以上 IP 结点的 Domain 结点关联的 IP 结点不是核心资产
    for t_node in core_nodes[:]:
        if categories[nodes[int(t_node)]["category"]]["name"] == "Domain":
            # ip_num = 0
            ip_nodes = []
            for target in adjacency.get(t_node, []):
                if categories[target["category"]]["name"] == "IP":
                    ip_nodes.append(target['target'])
            if len(ip_nodes) > 2:
                for node in ip_nodes:
                    core_nodes.remove(node)

    return core_nodes


val = {
    "r_cert": 4,
    "r_subdomain": 4,
    "r_request_jump": 4,
    "r_dns_a": 4,
    "r_whois_name": 3,
    "r_whois_email": 3,
    "r_whois_phone": 3,
    "r_cert_chain": 2,
    "r_cname": 2,
    "r_asn": 1,
    "r_cidr": 1
}


def custom_key(path):
    with open("data/tmp.json", 'r') as f:
        adjacency = json.loads(f.read())

    path_len = len(path)
    res = 0

    if path_len == 4:
        score = 50
    if path_len == 3:
        score = 80
    if path_len == 2:
        score = 120
    for i in range(path_len - 1):
        start = path[i]
        end = path[i + 1]
        # print("path = ", path)
        # print("start = ", start)
        # print("end = ", end)
        for target in adjacency[str(start)]:
            # print("target = ", target['target'])
            if target["target"] == end:
                rel = target["rel"]
                break
        res += score * val[rel]

    return res / path_len


def getpath(paths):
    paths.sort(key=custom_key)
    paths.reverse()
    return paths


def bfskey(links, source_id, target_id):
    queue = [(source_id, 4)]
    pathnode = {}
    k = 4
    hop = 4
    path = []
    flag = 1
    index = 0
    while len(queue) != 0:
        id, jump = queue.pop(0)
        if id in links:
            for neighbour in links[id]:  # 得到一个list，里面是target 和 relation的二元组
                current_jump = min(jump, hop)  # current_jump 当前该结点展开的跳数

                if current_jump == 0:
                    if neighbour[0] in pathnode:
                        pathnode[str(neighbour[0])] += [id]
                    else:
                        pathnode[str(neighbour[0])] = [id]
                    if neighbour[0] == target_id:  # 找到
                        # 回溯
                        Apath = []
                        nextnode = target_id
                        nownode = neighbour[0]
                        while nextnode != source_id:
                            Apath.append(nextnode)
                            nextnode = pathnode[str(nownode)][0]
                            del pathnode[str(nownode)][0]
                            nownode = nextnode

                        Apath.append(source_id)
                        path.append(Apath)

                else:
                    if neighbour[0] in pathnode:
                        pathnode[str(neighbour[0])] += [id]
                    else:
                        pathnode[str(neighbour[0])] = [id]
                    if neighbour[0] == target_id and flag:  # 找到
                        # 回溯
                        Apath = []
                        nextnode = target_id
                        nownode = neighbour[0]

                        while nextnode != source_id:
                            Apath.append(nextnode)
                            nextnode = pathnode[str(nownode)][0]
                            del pathnode[str(nownode)][0]
                            nownode = nextnode

                        Apath.append(source_id)
                        path.append(Apath)
                        hop = 0
                        flag = 0
                        continue

                    queue += [(neighbour[0], current_jump - 1)]

    return path


def reverse_paths(paths):
    # paths: [path1, path2, ...]
    for path in paths:
        path.reverse()
    return paths


if __name__ == '__main__':
    # nodes, links = pickle.load(open("./data/data.pkl", "rb"))
    # print("read complete...")
    # analysis(nodes, links)

    # 将图的数据结构序列化到磁盘上, 加速读取
    nodes, links = read_node_and_link()
    data = [nodes, links]
    pickle.dump(data, open("./data/data.pkl", "wb"))

    link_source = []

    # 团伙1
    link_source += ["Domain_c58c149eec59bb14b0c102a0f303d4c20366926b5c3206555d2937474124beb9"]
    link_source += ["Domain_f3554b666038baffa5814c319d3053ee2c2eb30d31d0ef509a1a463386b69845"]

    # 团伙2
    # link_source += ["IP_400c19e584976ff2a35950659d4d148a3d146f1b71692468132b849b0eb8702c"]
    # link_source += ["Domain_b10f98a9b53806ccd3a5ee45676c7c09366545c5b12aa96955cde3953e7ad058"]

    # 团伙3
    # link_source += ["Domain_24acfd52f9ceb424d4a2643a832638ce1673b8689fa952d9010dd44949e6b1d9"]
    # link_source += ["Domain_9c72287c3f9bb38cb0186acf37b7054442b75ac32324dfd245aed46a03026de1"]
    # link_source += ["Domain_717aa5778731a1f4d6f0218dd3a27b114c839213b4af781427ac1e22dc9a7dea"]
    # link_source += ["Domain_8748687a61811032f0ed1dcdb57e01efef9983a6d9c236b82997b07477e66177"]
    # link_source += ["Whois_Phone_f4a84443fb72da27731660695dd00877e8ce25b264ec418504fface62cdcbbd7"]

    # 团伙4
    # link_source += ["IP_7e730b193c2496fc908086e8c44fc2dbbf7766e599fabde86a4bcb6afdaad66e"]
    # link_source += ["Cert_6724539e5c0851f37dcf91b7ac85cb35fcd9f8ba4df0107332c308aa53d63bdb"]

    # 团伙5
    # link_source += ["Whois_Phone_fd0a3f6712ff520edae7e554cb6dfb4bdd2af1e4a97a39ed9357b31b6888b4af"]
    # link_source += ["IP_21ce145cae6730a99300bf677b83bbe430cc0ec957047172e73659372f0031b8"]
    # link_source += ["Domain_7939d01c5b99c39d2a0f2b418f6060b917804e60c15309811ef4059257c0818a"]
    # link_source += ["Domain_587da0bac152713947db682a5443ef639e35f77a3b59e246e8a07c5eccae67e5"]

    print('------no limitation------')
    triple = bfs(nodes, links, link_source, hop_extra_limitation=False, k=3)
    statistic(nodes, triple)
    print('------with limitation------')
    triple = bfs(nodes, links, link_source, hop_extra_limitation=True, k=3)
    statistic(nodes, triple)
    # print('------with compression------')
    # graph = adjacency_list(triple)
    # triple = bfs_combine(nodes, graph, link_source)
    # statistic(nodes, triple, has_count=True)
    print('------analysis------')
    graph = adjacency_list(triple)
    analysis(nodes, graph)

    # echart = process_echart(nodes, triple)
    # with open("./out.json", "w") as f:
    #     json.dump(echart, f)

    # adjacency = get_adjacency(echart)
    # core_nodes = get_core(echart, adjacency)
    # print(core_nodes)
    # length = len(core_nodes)
    # alinks = {}
    # for line in echart["links"]:
    #     relation = line["value"]
    #     source = line["source"]
    #     target = line["target"]
    #     if source in alinks:
    #         alinks[source] += [(target, relation)]
    #     else:
    #         alinks[source] = [(target, relation)]
    # for i in range(0, length):
    #     for j in range(i + 1, length):
    #         # print("i = ", i)
    #         # print("j = ", j)
    #         temp = bfskey(alinks, core_nodes[i], core_nodes[j])
    #         temp = reverse_paths(temp)
    #         # print("temp = ", temp)
    #         paths = getpath(temp)
    #         print(paths)

    # link_source[1] = "Domain_f3554b666038baffa5814c319d3053ee2c2eb30d31d0ef509a1a463386b69845"  #
    # link_source[2] = "IP_400c19e584976ff2a35950659d4d148a3d146f1b71692468132b849b0eb8702c"
    # link_source[3] = "Domain_b10f98a9b53806ccd3a5ee45676c7c09366545c5b12aa96955cde3953e7ad058"  #
    # link_source[4] = "Domain_24acfd52f9ceb424d4a2643a832638ce1673b8689fa952d9010dd44949e6b1d9"
    # link_source[5] = "Domain_9c72287c3f9bb38cb0186acf37b7054442b75ac32324dfd245aed46a03026de1"
    # link_source[6] = "Domain_717aa5778731a1f4d6f0218dd3a27b114c839213b4af781427ac1e22dc9a7dea"
    # link_source[7] = "Domain_8748687a61811032f0ed1dcdb57e01efef9983a6d9c236b82997b07477e66177"
    # link_source[8] = "Whois_Phone_f4a84443fb72da27731660695dd00877e8ce25b264ec418504fface62cdcbbd7"
    # link_source[9] = "IP_7e730b193c2496fc908086e8c44fc2dbbf7766e599fabde86a4bcb6afdaad66e"
    # link_source[10] = "Cert_6724539e5c0851f37dcf91b7ac85cb35fcd9f8ba4df0107332c308aa53d63bdb"
    # link_source[11] = "Whois_Phone_fd0a3f6712ff520edae7e554cb6dfb4bdd2af1e4a97a39ed9357b31b6888b4af"
    # link_source[12] = "IP_21ce145cae6730a99300bf677b83bbe430cc0ec957047172e73659372f0031b8"
    # link_source[13] = "Domain_7939d01c5b99c39d2a0f2b418f6060b917804e60c15309811ef4059257c0818a"
    # link_source[14] = "Domain_587da0bac152713947db682a5443ef639e35f77a3b59e246e8a07c5eccae67e5"