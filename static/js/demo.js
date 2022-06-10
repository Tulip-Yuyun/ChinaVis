function showKG(query) {
    $.ajax({
        type: "get",
        url: "/knowledge_graph_search",
        data: {
            search: query
        },
        cache: false,
        success: function (data, status) {
            // console.log(data);
            if (data.entities.length > 0) {
                option = {
                    color: ['#4e88af', '#ca635f', '#d2907c', '#d6744d', '#ded295', '#6ca46c'],
                    tooltip: {
                        formatter: function (x) {
                            return x.data.description;
                        }
                    },
                    toolbox: {
                        show: true,
                        feature: {
                            mark: {
                                show: true
                            },
                            restore: {
                                show: true
                            },
                            saveAsImage: {
                                show: true
                            }
                        }
                    },
                    legend: [{
                        // selectedMode: 'single',
                        data: categories.map(function (a) {
                            return a.name;
                        })
                    }],
                    series: [{
                        type: 'graph', // 类型:关系图
                        layout: 'force', //图的布局，类型为力导图
                        symbolSize: 60, // 调整节点的大小
                        roam: true, // 是否开启鼠标缩放和平移漫游。默认不开启。如果只想要开启缩放或者平移,可以设置成 'scale' 或者 'move'。设置成 true 为都开启
                        edgeSymbol: ['circle', 'arrow'],
                        edgeSymbolSize: [2, 10],
                        edgeLabel: {
                            normal: {
                                textStyle: {
                                    fontSize: 20
                                }
                            },
                            show: true,
                                formatter: function (x) {
                                    return x.data.name;
                                }
                        },
                        force: {
                            repulsion: 2500,
                            edgeLength: [10, 50],
                            layoutAnimation: false,
                        },
                        draggable: true,
                        lineStyle: {
                            normal: {
                                width: 2,
                                color: '#C0C0C0',
                            }
                        },
                        label: {
                            normal: {
                                show: false,
                                textStyle: {}
                            }
                        },
                        // 数据
                        data: data.entities,
                        links: data.relations,
                        categories: categories
                    }]
                };
                myChart.setOption(option);
            } else {
                $('#no_result').show();
            }
        }
    });
}
   