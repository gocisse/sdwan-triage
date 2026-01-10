// SD-WAN Triage Report Visualizations
// Modern Dashboard with Theme Support

// Theme-aware color utilities
function getThemeColors() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
        primary: '#3b82f6',
        primaryLight: '#60a5fa',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        info: '#06b6d4',
        text: isDark ? '#f1f5f9' : '#1e293b',
        textSecondary: isDark ? '#94a3b8' : '#64748b',
        textMuted: isDark ? '#64748b' : '#94a3b8',
        background: isDark ? '#1e293b' : '#ffffff',
        border: isDark ? '#334155' : '#e2e8f0',
        nodeInternal: '#10b981',
        nodeRouter: '#3b82f6',
        nodeExternal: '#f59e0b',
        nodeAnomaly: '#ef4444'
    };
}

// Utility: Safe D3 initialization wrapper
function safeD3Init(containerId, initFn, data) {
    const container = document.getElementById(containerId);
    if (!container) {
        console.warn(`Container #${containerId} not found`);
        return;
    }
    
    // Remove loading message
    container.style.position = 'relative';
    const loadingMsg = container.querySelector('::before');
    
    if (!data || (Array.isArray(data) && data.length === 0) || 
        (data.nodes && data.nodes.length === 0)) {
        container.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-muted); font-size: 0.875rem;"><i class="fas fa-info-circle" style="margin-right: 8px;"></i>No data available for visualization</div>';
        return;
    }
    
    try {
        initFn(container, data);
        // Remove loading indicator after successful init
        container.style.minHeight = 'auto';
    } catch (error) {
        console.error(`Error initializing ${containerId}:`, error);
        container.innerHTML = `<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--danger); font-size: 0.875rem;"><i class="fas fa-exclamation-triangle" style="margin-right: 8px;"></i>Error rendering visualization: ${error.message}</div>`;
    }
}

// Network Diagram (Force-Directed Graph)
function createNetworkDiagram(container, data) {
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 500;
    
    // Validate data structure
    if (!data.nodes || !data.links) {
        throw new Error('Invalid network data structure');
    }
    
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
    
    // Color scale - theme aware
    const colors = getThemeColors();
    const colorScale = d3.scaleOrdinal()
        .domain(["internal", "router", "external", "anomaly"])
        .range([colors.nodeInternal, colors.nodeRouter, colors.nodeExternal, colors.nodeAnomaly]);
    
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
    
    // Legend - theme aware
    const legend = svg.append("g").attr("transform", `translate(20, 20)`);
    const legendData = [
        { label: "Internal", color: colors.nodeInternal },
        { label: "Router/Gateway", color: colors.nodeRouter },
        { label: "External", color: colors.nodeExternal },
        { label: "Anomaly", color: colors.nodeAnomaly }
    ];
    legendData.forEach((item, i) => {
        const lg = legend.append("g").attr("transform", `translate(0, ${i * 22})`);
        lg.append("circle").attr("r", 6).attr("fill", item.color);
        lg.append("text").attr("x", 12).attr("y", 4).attr("font-size", "11px").attr("fill", colors.text).text(item.label);
    });
}

// Timeline Visualization
function createTimeline(container, data) {
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 300;
    
    if (!Array.isArray(data) || data.length === 0) {
        throw new Error('No timeline data available');
    }
    const margin = { top: 30, right: 30, bottom: 50, left: 60 };
    const colors = getThemeColors();
    
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
        .attr("fill", colors.text)
        .text("Event Timeline");
}

// Sankey Diagram
function createSankeyDiagram(container, data) {
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 400;
    
    if (!data.nodes || !data.links) {
        throw new Error('Invalid sankey data structure');
    }
    const margin = { top: 20, right: 120, bottom: 20, left: 120 };
    const colors = getThemeColors();
    
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
        .attr("fill", colors.text)
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

// Protocol Distribution Pie Chart
function createProtocolChart(container, data) {
    const width = container.clientWidth || 400;
    const height = container.clientHeight || 350;
    
    if (!Array.isArray(data) || data.length === 0) {
        throw new Error('No protocol data available');
    }
    const radius = Math.min(width, height) / 2 - 40;
    const colors = getThemeColors();
    
    d3.select(container).selectAll("*").remove();
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height);
    
    const g = svg.append("g")
        .attr("transform", `translate(${width / 2}, ${height / 2})`);
    
    // Tooltip
    const tooltip = d3.select("body").append("div")
        .attr("class", "d3-tooltip")
        .style("opacity", 0);
    
    // Pie generator
    const pie = d3.pie()
        .value(d => d.Bytes)
        .sort(null);
    
    // Arc generator
    const arc = d3.arc()
        .innerRadius(radius * 0.5)
        .outerRadius(radius);
    
    const arcHover = d3.arc()
        .innerRadius(radius * 0.5)
        .outerRadius(radius * 1.1);
    
    // Draw slices
    const slices = g.selectAll("path")
        .data(pie(data))
        .join("path")
        .attr("d", arc)
        .attr("fill", d => d.data.Color || "#667eea")
        .attr("stroke", "white")
        .attr("stroke-width", 2)
        .on("mouseover", function(event, d) {
            d3.select(this).transition().duration(200).attr("d", arcHover);
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.data.Protocol}</strong><br/>
                ${formatBytes(d.data.Bytes)}<br/>
                ${d.data.Percent.toFixed(1)}%`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            d3.select(this).transition().duration(200).attr("d", arc);
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Center text
    g.append("text")
        .attr("text-anchor", "middle")
        .attr("dy", "-0.5em")
        .attr("font-size", "14px")
        .attr("font-weight", "bold")
        .attr("fill", colors.text)
        .text("Protocol");
    
    g.append("text")
        .attr("text-anchor", "middle")
        .attr("dy", "1em")
        .attr("font-size", "12px")
        .attr("fill", colors.textSecondary)
        .text("Distribution");
    
    // Legend
    const legend = svg.append("g")
        .attr("transform", `translate(${width - 120}, 30)`);
    
    data.forEach((d, i) => {
        const lg = legend.append("g")
            .attr("transform", `translate(0, ${i * 25})`);
        lg.append("rect")
            .attr("width", 18)
            .attr("height", 18)
            .attr("fill", d.Color || colors.primary);
        lg.append("text")
            .attr("x", 24)
            .attr("y", 14)
            .attr("font-size", "12px")
            .attr("fill", colors.text)
            .text(`${d.Protocol} (${d.Percent.toFixed(1)}%)`);
    });
}

// Top Talkers Bar Chart
function createTopTalkersChart(container, data) {
    const width = container.clientWidth || 600;
    const height = container.clientHeight || 350;
    
    if (!Array.isArray(data) || data.length === 0) {
        throw new Error('No traffic data available');
    }
    
    // Limit to top 10 for better visualization
    data = data.slice(0, 10);
    const margin = { top: 30, right: 30, bottom: 60, left: 150 };
    const colors = getThemeColors();
    
    d3.select(container).selectAll("*").remove();
    
    if (!data || data.length === 0) {
        container.innerHTML = '<div class="viz-error">No traffic data available</div>';
        return;
    }
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height);
    
    const g = svg.append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);
    
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;
    
    // Tooltip
    const tooltip = d3.select("body").append("div")
        .attr("class", "d3-tooltip")
        .style("opacity", 0);
    
    // Scales
    const x = d3.scaleLinear()
        .domain([0, d3.max(data, d => d.Bytes)])
        .range([0, innerWidth]);
    
    const y = d3.scaleBand()
        .domain(data.map(d => d.IP))
        .range([0, innerHeight])
        .padding(0.2);
    
    // Color scale - theme aware
    const colorScale = d3.scaleOrdinal()
        .domain(["internal", "external"])
        .range([colors.success, colors.primary]);
    
    // Bars
    g.selectAll("rect")
        .data(data)
        .join("rect")
        .attr("x", 0)
        .attr("y", d => y(d.IP))
        .attr("width", d => x(d.Bytes))
        .attr("height", y.bandwidth())
        .attr("fill", d => colorScale(d.Type))
        .attr("rx", 4)
        .on("mouseover", function(event, d) {
            d3.select(this).attr("opacity", 0.8);
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.IP}</strong><br/>
                Traffic: ${formatBytes(d.Bytes)}<br/>
                ${d.Percent.toFixed(1)}% of total<br/>
                Type: ${d.Type}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            d3.select(this).attr("opacity", 1);
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Labels on bars
    g.selectAll(".bar-label")
        .data(data)
        .join("text")
        .attr("class", "bar-label")
        .attr("x", d => x(d.Bytes) + 5)
        .attr("y", d => y(d.IP) + y.bandwidth() / 2)
        .attr("dy", "0.35em")
        .attr("font-size", "11px")
        .attr("fill", colors.text)
        .text(d => formatBytes(d.Bytes));
    
    // Y axis (IPs)
    g.append("g")
        .call(d3.axisLeft(y))
        .selectAll("text")
        .attr("font-size", "11px");
    
    // X axis
    g.append("g")
        .attr("transform", `translate(0,${innerHeight})`)
        .call(d3.axisBottom(x).ticks(5).tickFormat(d => formatBytes(d)));
    
    // Title
    svg.append("text")
        .attr("x", width / 2)
        .attr("y", 15)
        .attr("text-anchor", "middle")
        .attr("font-size", "14px")
        .attr("font-weight", "bold")
        .attr("fill", colors.text)
        .text("Top Talkers by Traffic Volume");
    
    // Legend
    const legend = svg.append("g")
        .attr("transform", `translate(${width - 150}, ${height - 30})`);
    
    [{ label: "Internal", color: colors.success }, { label: "External", color: colors.primary }].forEach((item, i) => {
        const lg = legend.append("g")
            .attr("transform", `translate(${i * 80}, 0)`);
        lg.append("rect")
            .attr("width", 14)
            .attr("height", 14)
            .attr("fill", item.color);
        lg.append("text")
            .attr("x", 18)
            .attr("y", 11)
            .attr("font-size", "11px")
            .attr("fill", colors.text)
            .text(item.label);
    });
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
        const isVisible = actionRow.classList.contains('show');
        actionRow.classList.toggle('show');
        actionRow.style.display = isVisible ? 'none' : 'table-row';
        btn.textContent = isVisible ? 'Show Action' : 'Hide Action';
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initTabs();
    initTableSorting();
    
    // Add small delay to ensure DOM is fully ready
    setTimeout(function() {
        // Initialize visualizations if data exists
        if (typeof protocolStats !== 'undefined' && protocolStats) {
            safeD3Init('protocol-chart', createProtocolChart, protocolStats);
        }
        if (typeof topTalkers !== 'undefined' && topTalkers) {
            safeD3Init('top-talkers-chart', createTopTalkersChart, topTalkers);
        }
        if (typeof networkData !== 'undefined' && networkData) {
            safeD3Init('network-diagram-viz', createNetworkDiagram, networkData);
        }
        if (typeof timelineData !== 'undefined' && timelineData) {
            safeD3Init('timeline-diagram', createTimeline, timelineData);
        }
        if (typeof sankeyData !== 'undefined' && sankeyData) {
            safeD3Init('sankey-diagram', createSankeyDiagram, sankeyData);
        }
    }, 100);
    
    // Re-render visualizations on window resize
    let resizeTimeout;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(function() {
            if (typeof protocolStats !== 'undefined' && protocolStats) {
                safeD3Init('protocol-chart', createProtocolChart, protocolStats);
            }
            if (typeof topTalkers !== 'undefined' && topTalkers) {
                safeD3Init('top-talkers-chart', createTopTalkersChart, topTalkers);
            }
            if (typeof networkData !== 'undefined' && networkData) {
                safeD3Init('network-diagram-viz', createNetworkDiagram, networkData);
            }
            if (typeof timelineData !== 'undefined' && timelineData) {
                safeD3Init('timeline-diagram', createTimeline, timelineData);
            }
            if (typeof sankeyData !== 'undefined' && sankeyData) {
                safeD3Init('sankey-diagram', createSankeyDiagram, sankeyData);
            }
        }, 250);
    });
});
