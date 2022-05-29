import csv
import json
import random


def read_node_and_link():
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
        if source in links:
            links[source] += [(target, relation)]
        else:
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


# 判断该条relation下应该挖掘几跳
# hop里面的数值对应多少跳
def relation_hop():
    hop = {
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
    return hop


def bfs(links, source_id, k=3):
    """
    bfs 找到k跳以内的三元组
    """
    queue = [(source_id, 3)]
    triple = []
    hop = relation_hop()
    while len(queue) != 0:
        id, jump = queue.pop(0)
        if id in links:
            for neighbour in links[id]:  # 得到一个list，里面是target 和 relation的二元组
                current_jump = min(jump, hop[neighbour[1]])  # current_jump 当前该结点展开的跳数
                if current_jump == 1:
                    triple += [(id, neighbour[0], neighbour[1])]  # 一跳之后存储源目的边三元组,但是不参与后面的展开了，你的使命到此为止～
                else:
                    queue += [(neighbour[0], current_jump - 1)]  # 跳了一步后，剩余可以跳的步数-1，深度+1，继续放到点展开的queue中
                    triple += [(id, neighbour[0], neighbour[1])]  # 一跳之后存储源目的边三元组
    return triple


def process_echart(nodes, triple):
    """
    转换成echart数据格式
    """
    node_echart = []
    link_echart = []
    category_echart = []
    type_map = {}
    type_index = 0
    node_map = {}
    node_index = 0
    for source, target, relation in triple:
        source_type = nodes[source]["type"]  # get source type
        target_type = nodes[target]["type"]  # get target type
        # map node type to index
        if source_type not in type_map:  # 建立不重复边的map
            type_map[source_type] = type_index  # 如果是新的边则更新index 并且++
            type_index += 1
        if target_type not in type_map:  # 建立不重复边的map
            type_map[target_type] = type_index  # 如果是新的边则更新index 并且++
            type_index += 1
        # map node id to index
        if source not in node_map:
            node_map[source] = node_index  # 同样的作为源和目的都是node 排除掉重复出现的node
            node_index += 1
        if target not in node_map:
            node_map[target] = node_index
            node_index += 1
        # echart link
        link_echart += [{"source": node_map[source], "target": node_map[target], "value": relation}]

    # echart node
    for node in node_map:
        node_echart += [{"id": node_map[node], "category": type_map[nodes[node]["type"]],
                         "symbolSize": random.randint(10, 50), "name": node[-5:]}]
    # echart category
    categories = sorted(type_map.items(), key=lambda kv: kv[1])
    for category in categories:
        category_echart += [{"name": category[0]}]
    echart = {"nodes": node_echart, "links": link_echart, "categories": category_echart}

    return echart


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
    nodes, links = read_node_and_link()

    link_source = []
    link_source += ["Domain_c58c149eec59bb14b0c102a0f303d4c20366926b5c3206555d2937474124beb9"]
    triple = bfs(links, link_source[0])
    echart = process_echart(nodes, triple)
    adjacency = get_adjacency(echart)
    core_nodes = get_core(echart, adjacency)
    print(core_nodes)
    length = len(core_nodes)
    alinks = {}
    for line in echart["links"]:
        relation = line["value"]
        source = line["source"]
        target = line["target"]
        if source in alinks:
            alinks[source] += [(target, relation)]
        else:
            alinks[source] = [(target, relation)]
    for i in range(0, length):
        for j in range(i + 1, length):
            # print("i = ", i)
            # print("j = ", j)
            temp = bfskey(alinks, core_nodes[i], core_nodes[j])
            temp = reverse_paths(temp)
            # print("temp = ", temp)
            paths = getpath(temp)
            print(paths)

    # with open("./out.json", "w") as f:
    #     json.dump(x, f)

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
