// SD-WAN Triage Report Visualizations

// Utility: Safe D3 initialization wrapper
function safeD3Init(containerId, initFn, data) {
    const container = document.getElementById(containerId);
    if (!container) {
        console.warn(`Container #${containerId} not found`);
        return;
    }
    
    if (!data || (Array.isArray(data) && data.length === 0) || 
        (data.nodes && data.nodes.length === 0)) {
        container.innerHTML = '<div class="viz-error"><i class="fas fa-info-circle"></i>&nbsp;No data available for visualization</div>';
        return;
    }
    
    try {
        initFn(container, data);
    } catch (error) {
        console.error(`Error initializing ${containerId}:`, error);
        container.innerHTML = `<div class="viz-error"><i class="fas fa-exclamation-triangle"></i>&nbsp;Error rendering visualization: ${error.message}</div>`;
    }
}

// Network Diagram (Force-Directed Graph)
function createNetworkDiagram(container, data) {
    const width = container.clientWidth || 800;
    const height = 500;
    
    // Clear existing content
    d3.select(container).selectAll("*").remove();
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height)
        .attr("viewBox", [0, 0, width, height]);
    
    // Zoom behavior
    const g = svg.append("g");
    svg.call(d3.zoom()
        .scaleExtent([0.1, 4])
        .on("zoom", (event) => g.attr("transform", event.transform)));
    
    // Tooltip
    const tooltip = d3.select("body").append("div")
        .attr("class", "d3-tooltip")
        .style("opacity", 0);
    
    // Color scale
    const colorScale = d3.scaleOrdinal()
        .domain(["internal", "router", "external", "anomaly"])
        .range(["#66cc66", "#6699ff", "#ff9933", "#dc3545"]);
    
    // Force simulation
    const simulation = d3.forceSimulation(data.nodes)
        .force("link", d3.forceLink(data.links).id(d => d.id).distance(120))
        .force("charge", d3.forceManyBody().strength(-250))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(35));
    
    // Links
    const link = g.append("g")
        .selectAll("line")
        .data(data.links)
        .join("line")
        .attr("stroke", d => d.hasIssue ? "#dc3545" : "#999")
        .attr("stroke-opacity", 0.6)
        .attr("stroke-width", d => Math.max(1, Math.sqrt(d.value || 1)))
        .attr("stroke-dasharray", d => d.hasIssue ? "5,5" : "0");
    
    // Nodes
    const node = g.append("g")
        .selectAll("circle")
        .data(data.nodes)
        .join("circle")
        .attr("r", d => d.group === "router" ? 12 : 8)
        .attr("fill", d => colorScale(d.group))
        .attr("stroke", "#fff")
        .attr("stroke-width", 2)
        .call(drag(simulation))
        .on("mouseover", function(event, d) {
            d3.select(this).attr("r", d.group === "router" ? 16 : 12);
            highlightConnections(d, true);
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.label || d.id}</strong><br/>Type: ${d.group}${d.bytes ? '<br/>Traffic: ' + formatBytes(d.bytes) : ''}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function(event, d) {
            d3.select(this).attr("r", d.group === "router" ? 12 : 8);
            highlightConnections(d, false);
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Labels
    const labels = g.append("g")
        .selectAll("text")
        .data(data.nodes)
        .join("text")
        .attr("class", "node-label")
        .attr("dx", 12)
        .attr("dy", 4)
        .text(d => d.label || d.id);
    
    // Highlight connections
    function highlightConnections(d, highlight) {
        link.attr("stroke-opacity", l => {
            if (highlight && (l.source.id === d.id || l.target.id === d.id)) return 1;
            return highlight ? 0.1 : 0.6;
        });
        node.attr("opacity", n => {
            if (!highlight) return 1;
            if (n.id === d.id) return 1;
            const connected = data.links.some(l => 
                (l.source.id === d.id && l.target.id === n.id) ||
                (l.target.id === d.id && l.source.id === n.id)
            );
            return connected ? 1 : 0.2;
        });
    }
    
    // Simulation tick
    simulation.on("tick", () => {
        link.attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);
        node.attr("cx", d => d.x).attr("cy", d => d.y);
        labels.attr("x", d => d.x).attr("y", d => d.y);
    });
    
    // Drag behavior
    function drag(simulation) {
        return d3.drag()
            .on("start", (event, d) => {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x; d.fy = d.y;
            })
            .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
            .on("end", (event, d) => {
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null; d.fy = null;
            });
    }
    
    // Legend
    const legend = svg.append("g").attr("transform", `translate(20, 20)`);
    const legendData = [
        { label: "Internal", color: "#66cc66" },
        { label: "Router/Gateway", color: "#6699ff" },
        { label: "External", color: "#ff9933" },
        { label: "Anomaly", color: "#dc3545" }
    ];
    legendData.forEach((item, i) => {
        const lg = legend.append("g").attr("transform", `translate(0, ${i * 22})`);
        lg.append("circle").attr("r", 6).attr("fill", item.color);
        lg.append("text").attr("x", 12).attr("y", 4).attr("font-size", "11px").text(item.label);
    });
}

// Timeline Visualization
function createTimeline(container, data) {
    const width = container.clientWidth || 800;
    const height = 300;
    const margin = { top: 30, right: 30, bottom: 50, left: 60 };
    
    d3.select(container).selectAll("*").remove();
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height);
    
    const g = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;
    
    // Parse timestamps
    const parseTime = d => new Date(d * 1000);
    data.forEach(d => d.time = parseTime(d.timestamp));
    
    // Scales
    const x = d3.scaleTime()
        .domain(d3.extent(data, d => d.time))
        .range([0, innerWidth]);
    
    const eventTypes = [...new Set(data.map(d => d.type))];
    const y = d3.scaleBand()
        .domain(eventTypes)
        .range([0, innerHeight])
        .padding(0.3);
    
    const colorScale = d3.scaleOrdinal()
        .domain(eventTypes)
        .range(d3.schemeCategory10);
    
    // Tooltip
    const tooltip = d3.select("body").append("div")
        .attr("class", "d3-tooltip")
        .style("opacity", 0);
    
    // Axes
    g.append("g")
        .attr("class", "timeline-axis")
        .attr("transform", `translate(0,${innerHeight})`)
        .call(d3.axisBottom(x).ticks(6));
    
    g.append("g")
        .attr("class", "timeline-axis")
        .call(d3.axisLeft(y));
    
    // Events
    g.selectAll(".timeline-event")
        .data(data)
        .join("circle")
        .attr("class", "timeline-event")
        .attr("cx", d => x(d.time))
        .attr("cy", d => y(d.type) + y.bandwidth() / 2)
        .attr("r", 6)
        .attr("fill", d => colorScale(d.type))
        .attr("stroke", "#fff")
        .attr("stroke-width", 1)
        .on("mouseover", function(event, d) {
            d3.select(this).attr("r", 10);
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.type}</strong><br/>
                Time: ${d.time.toLocaleTimeString()}<br/>
                ${d.source ? 'Source: ' + d.source + '<br/>' : ''}
                ${d.target ? 'Target: ' + d.target + '<br/>' : ''}
                ${d.detail || ''}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            d3.select(this).attr("r", 6);
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Title
    svg.append("text")
        .attr("x", width / 2)
        .attr("y", 15)
        .attr("text-anchor", "middle")
        .attr("font-size", "14px")
        .attr("font-weight", "bold")
        .text("Event Timeline");
}

// Sankey Diagram
function createSankeyDiagram(container, data) {
    const width = container.clientWidth || 800;
    const height = 400;
    const margin = { top: 20, right: 120, bottom: 20, left: 120 };
    
    d3.select(container).selectAll("*").remove();
    
    if (!data.nodes || !data.links || data.links.length === 0) {
        container.innerHTML = '<div class="viz-error">No traffic flow data available</div>';
        return;
    }
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height);
    
    const g = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;
    
    // Sankey generator
    const sankey = d3.sankey()
        .nodeWidth(20)
        .nodePadding(15)
        .extent([[0, 0], [innerWidth, innerHeight]]);
    
    const { nodes, links } = sankey({
        nodes: data.nodes.map(d => Object.assign({}, d)),
        links: data.links.map(d => Object.assign({}, d))
    });
    
    // Tooltip
    const tooltip = d3.select("body").append("div")
        .attr("class", "d3-tooltip")
        .style("opacity", 0);
    
    // Color scale
    const color = d3.scaleOrdinal(d3.schemeCategory10);
    
    // Links
    g.append("g")
        .selectAll("path")
        .data(links)
        .join("path")
        .attr("class", "sankey-link")
        .attr("d", d3.sankeyLinkHorizontal())
        .attr("stroke", d => color(d.source.name))
        .attr("stroke-width", d => Math.max(1, d.width))
        .on("mouseover", function(event, d) {
            d3.select(this).attr("stroke-opacity", 0.7);
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.source.name} → ${d.target.name}</strong><br/>Traffic: ${formatBytes(d.value)}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            d3.select(this).attr("stroke-opacity", 0.4);
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Nodes
    g.append("g")
        .selectAll("rect")
        .data(nodes)
        .join("rect")
        .attr("x", d => d.x0)
        .attr("y", d => d.y0)
        .attr("height", d => Math.max(1, d.y1 - d.y0))
        .attr("width", d => d.x1 - d.x0)
        .attr("fill", d => color(d.name))
        .attr("stroke", "#000")
        .on("mouseover", function(event, d) {
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.name}</strong><br/>Total: ${formatBytes(d.value)}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Node labels
    g.append("g")
        .selectAll("text")
        .data(nodes)
        .join("text")
        .attr("x", d => d.x0 < innerWidth / 2 ? d.x1 + 6 : d.x0 - 6)
        .attr("y", d => (d.y1 + d.y0) / 2)
        .attr("dy", "0.35em")
        .attr("text-anchor", d => d.x0 < innerWidth / 2 ? "start" : "end")
        .attr("font-size", "12px")
        .text(d => d.name);
}

// Utility: Format bytes
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Tab functionality
function initTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', function() {
            const tabGroup = this.closest('.card');
            tabGroup.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            tabGroup.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            this.classList.add('active');
            const target = document.getElementById(this.dataset.tab);
            if (target) target.classList.add('active');
        });
    });
}

// Table sorting
function initTableSorting() {
    document.querySelectorAll('.data-table th[data-sort]').forEach(th => {
        th.addEventListener('click', function() {
            const table = this.closest('table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr:not(.action-row)'));
            const col = this.cellIndex;
            const isAsc = this.classList.contains('sort-asc');
            
            rows.sort((a, b) => {
                const aVal = a.cells[col].textContent.trim();
                const bVal = b.cells[col].textContent.trim();
                const aNum = parseFloat(aVal.replace(/[^0-9.-]/g, ''));
                const bNum = parseFloat(bVal.replace(/[^0-9.-]/g, ''));
                
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return isAsc ? bNum - aNum : aNum - bNum;
                }
                return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
            });
            
            table.querySelectorAll('th').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
            this.classList.add(isAsc ? 'sort-desc' : 'sort-asc');
            
            rows.forEach(row => {
                const actionRow = row.nextElementSibling;
                tbody.appendChild(row);
                if (actionRow && actionRow.classList.contains('action-row')) {
                    tbody.appendChild(actionRow);
                }
            });
        });
    });
}

// Toggle action visibility
function toggleAction(btn) {
    const row = btn.closest('tr');
    const actionRow = row.nextElementSibling;
    if (actionRow && actionRow.classList.contains('action-row')) {
        const isVisible = actionRow.classList.contains('visible');
        actionRow.classList.toggle('visible');
        btn.textContent = isVisible ? 'Show Action' : 'Hide Action';
        btn.classList.toggle('btn-secondary', isVisible);
        btn.classList.toggle('btn-success', !isVisible);
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initTabs();
    initTableSorting();
    
    // Initialize visualizations if data exists
    if (typeof networkData !== 'undefined') {
        safeD3Init('network-diagram', createNetworkDiagram, networkData);
    }
    if (typeof timelineData !== 'undefined') {
        safeD3Init('timeline-diagram', createTimeline, timelineData);
    }
    if (typeof sankeyData !== 'undefined') {
        safeD3Init('sankey-diagram', createSankeyDiagram, sankeyData);
    }
});
