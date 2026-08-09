// CYPHRA Business Website — Chart.js Configurations
// Professional Corporate Color Palette — All data in ₹ (Indian Rupees)

Chart.defaults.font.family = "'Inter', 'Segoe UI', sans-serif";
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = '#1e293b';

const C = {
    blue: '#4f7df5',
    blueDim: '#3b66d9',
    sky: '#38bdf8',
    skyDim: '#0ea5e9',
    amber: '#f0a03c',
    amberDim: '#d98f2e',
    emerald: '#34d399',
    rose: '#f43f5e',
    purple: '#a78bfa',
    yellow: '#fbbf24',
    teal: '#2dd4bf',
    text: '#e2e8f0',
    muted: '#94a3b8',
    gridLine: 'rgba(148, 163, 184, 0.06)',
};

const defaultLegend = { position: 'top', labels: { color: C.text, padding: 15, usePointStyle: true, font: { size: 12 } } };
const defaultGrid = { color: C.gridLine };

// ============================================================
// HOME PAGE — 5-Year Revenue & Profit Line Chart
// ============================================================
const revenueChartEl = document.getElementById('revenueChart');
if (revenueChartEl) {
    new Chart(revenueChartEl, {
        type: 'line',
        data: {
            labels: ['Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5'],
            datasets: [{
                label: 'Revenue (₹ Lakhs)',
                data: [18, 120, 450, 800, 1200],
                borderColor: C.blue,
                backgroundColor: C.blue + '12',
                borderWidth: 2.5, fill: true, tension: 0.4,
                pointBackgroundColor: C.blue, pointBorderColor: '#151e2e', pointBorderWidth: 2, pointRadius: 5
            }, {
                label: 'Net Profit (₹ Lakhs)',
                data: [-20, -5, 95, 280, 480],
                borderColor: C.emerald,
                backgroundColor: C.emerald + '10',
                borderWidth: 2.5, fill: true, tension: 0.4,
                pointBackgroundColor: C.emerald, pointBorderColor: '#151e2e', pointBorderWidth: 2, pointRadius: 5
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: '5-Year Revenue & Net Profit Projection (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                y: { grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } },
                x: { grid: defaultGrid, ticks: { color: C.muted } }
            }
        }
    });
}

// ============================================================
// STARTUP COSTS — Doughnut Chart
// ============================================================
const fundsChartEl = document.getElementById('fundsChart');
if (fundsChartEl) {
    new Chart(fundsChartEl, {
        type: 'doughnut',
        data: {
            labels: ['Infrastructure & Deployment (₹4L)', 'Certifications & Compliance (₹3L)', 'Marketing & BD (₹3L)', 'Legal & IP (₹2L)', 'Operations (₹1.5L)', 'Hardware & Demo (₹1.5L)'],
            datasets: [{
                data: [4, 3, 3, 2, 1.5, 1.5],
                backgroundColor: [C.blue, C.sky, C.purple, C.amber, C.teal, C.yellow],
                borderWidth: 2, borderColor: '#151e2e',
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            cutout: '60%',
            plugins: {
                title: { display: true, text: 'Startup Cost Breakdown (₹15 Lakhs Total)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: { position: 'bottom', labels: { color: C.text, padding: 12, usePointStyle: true, font: { size: 11 } } }
            }
        }
    });
}

// ============================================================
// STARTUP COSTS — Monthly Burn Rate Bar Chart
// ============================================================
const burnChartEl = document.getElementById('burnChart');
if (burnChartEl) {
    new Chart(burnChartEl, {
        type: 'bar',
        data: {
            labels: ['M1', 'M2', 'M3', 'M4', 'M5', 'M6', 'M7', 'M8', 'M9', 'M10', 'M11', 'M12'],
            datasets: [{
                label: 'Monthly Burn (₹ Lakhs)',
                data: [2.5, 1.8, 1.5, 1.5, 1.2, 1.2, 1.0, 1.0, 1.0, 0.8, 0.8, 0.7],
                backgroundColor: C.rose + '80',
                borderColor: C.rose,
                borderWidth: 1, borderRadius: 4
            }, {
                label: 'Monthly Revenue (₹ Lakhs)',
                data: [0, 0, 0, 0, 0, 0.5, 0.8, 1.0, 1.2, 1.5, 1.5, 1.5],
                backgroundColor: C.emerald + '80',
                borderColor: C.emerald,
                borderWidth: 1, borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Year 1 Monthly Burn vs Revenue (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}

// ============================================================
// REVENUE — Customer Growth Bar Chart
// ============================================================
const customerGrowthEl = document.getElementById('customerGrowthChart');
if (customerGrowthEl) {
    new Chart(customerGrowthEl, {
        type: 'bar',
        data: {
            labels: ['Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5'],
            datasets: [{
                label: 'SOC Standard',
                data: [3, 10, 25, 45, 60],
                backgroundColor: C.blue, borderRadius: 3
            }, {
                label: 'SOC + DOC Pro',
                data: [0, 2, 8, 15, 20],
                backgroundColor: C.sky, borderRadius: 3
            }, {
                label: 'Full Platform',
                data: [0, 1, 3, 6, 8],
                backgroundColor: C.purple, borderRadius: 3
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Customer Acquisition by Tier', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { stacked: true, grid: defaultGrid, ticks: { color: C.muted } },
                y: { stacked: true, grid: defaultGrid, ticks: { color: C.muted } }
            }
        }
    });
}

// ============================================================
// REVENUE — Revenue by Tier Stacked Bar
// ============================================================
const revenueTierEl = document.getElementById('revenueTierChart');
if (revenueTierEl) {
    new Chart(revenueTierEl, {
        type: 'bar',
        data: {
            labels: ['Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5'],
            datasets: [{
                label: 'SOC Standard (₹50K/mo)',
                data: [18, 60, 150, 270, 360],
                backgroundColor: C.blue, borderRadius: 3
            }, {
                label: 'SOC + DOC Pro (₹1.5L/mo)',
                data: [0, 36, 144, 270, 360],
                backgroundColor: C.sky, borderRadius: 3
            }, {
                label: 'Full Platform (₹3L/mo + users)',
                data: [0, 24, 156, 260, 480],
                backgroundColor: C.purple, borderRadius: 3
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: '5-Year Revenue by Tier (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { stacked: true, grid: defaultGrid, ticks: { color: C.muted } },
                y: { stacked: true, grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}

// ============================================================
// REVENUE — MRR Growth Line
// ============================================================
const mrrGrowthEl = document.getElementById('mrrGrowthChart');
if (mrrGrowthEl) {
    new Chart(mrrGrowthEl, {
        type: 'line',
        data: {
            labels: ['Y1-Q1', 'Y1-Q2', 'Y1-Q3', 'Y1-Q4', 'Y2-Q1', 'Y2-Q2', 'Y2-Q3', 'Y2-Q4', 'Y3-Q1', 'Y3-Q2', 'Y3-Q3', 'Y3-Q4'],
            datasets: [{
                label: 'MRR (₹ Lakhs)',
                data: [0.5, 0.8, 1.2, 1.5, 4, 7, 9, 10, 20, 28, 34, 37.5],
                borderColor: C.blue,
                backgroundColor: C.blue + '10',
                borderWidth: 2.5, fill: true, tension: 0.3,
                pointBackgroundColor: C.blue, pointBorderColor: '#151e2e', pointBorderWidth: 2, pointRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Monthly Recurring Revenue Growth (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}

// ============================================================
// EXPENSES — Stacked Bar by Category
// ============================================================
const expenseChartEl = document.getElementById('expenseChart');
if (expenseChartEl) {
    new Chart(expenseChartEl, {
        type: 'bar',
        data: {
            labels: ['Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5'],
            datasets: [{
                label: 'Personnel',
                data: [10, 30, 65, 110, 150],
                backgroundColor: C.blue, borderRadius: 3
            }, {
                label: 'Marketing & BD',
                data: [3, 12, 30, 45, 60],
                backgroundColor: C.sky, borderRadius: 3
            }, {
                label: 'Infrastructure',
                data: [2, 5, 12, 18, 25],
                backgroundColor: C.amber, borderRadius: 3
            }, {
                label: 'Compliance & Legal',
                data: [3, 4, 6, 10, 15],
                backgroundColor: C.purple, borderRadius: 3
            }, {
                label: 'Operations',
                data: [2, 4, 7, 12, 15],
                backgroundColor: C.teal, borderRadius: 3
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Operating Expenses by Category (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { stacked: true, grid: defaultGrid, ticks: { color: C.muted } },
                y: { stacked: true, grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}

// ============================================================
// EXPENSES — Team Scaling Area Chart
// ============================================================
const teamChartEl = document.getElementById('teamChart');
if (teamChartEl) {
    new Chart(teamChartEl, {
        type: 'line',
        data: {
            labels: ['Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5'],
            datasets: [{
                label: 'Engineering',
                data: [2, 4, 7, 9, 12],
                borderColor: C.blue, backgroundColor: C.blue + '15',
                fill: true, tension: 0.4, borderWidth: 2
            }, {
                label: 'Sales & BD',
                data: [0, 1, 3, 5, 6],
                borderColor: C.amber, backgroundColor: C.amber + '15',
                fill: true, tension: 0.4, borderWidth: 2
            }, {
                label: 'Operations & Support',
                data: [0, 1, 2, 4, 6],
                borderColor: C.teal, backgroundColor: C.teal + '15',
                fill: true, tension: 0.4, borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Team Scaling Plan (Headcount)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { grid: defaultGrid, ticks: { color: C.muted, stepSize: 5 } }
            }
        }
    });
}

// ============================================================
// CASH FLOW — Monthly Revenue vs Expenses (Year 1)
// ============================================================
const cashFlowEl = document.getElementById('cashFlowChart');
if (cashFlowEl) {
    new Chart(cashFlowEl, {
        type: 'line',
        data: {
            labels: ['M1', 'M2', 'M3', 'M4', 'M5', 'M6', 'M7', 'M8', 'M9', 'M10', 'M11', 'M12'],
            datasets: [{
                label: 'Monthly Revenue',
                data: [0, 0, 0, 0, 0, 0.5, 0.8, 1.0, 1.2, 1.5, 1.5, 1.5],
                borderColor: C.emerald, backgroundColor: C.emerald + '08',
                borderWidth: 2, fill: true, tension: 0.4
            }, {
                label: 'Monthly Expenses',
                data: [2.5, 1.8, 1.5, 1.5, 1.2, 1.2, 1.0, 1.0, 1.0, 0.8, 0.8, 0.7],
                borderColor: C.rose, backgroundColor: C.rose + '08',
                borderWidth: 2, fill: true, tension: 0.4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Year 1 Cash Flow — Revenue vs Expenses (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}

// ============================================================
// CASH FLOW — Cumulative Cash Flow Bar
// ============================================================
const cumulativeCashEl = document.getElementById('cumulativeCashChart');
if (cumulativeCashEl) {
    new Chart(cumulativeCashEl, {
        type: 'bar',
        data: {
            labels: ['Year 0', 'Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5'],
            datasets: [{
                label: 'Cumulative Cash Flow (₹ Lakhs)',
                data: [-15, -17, 5, 100, 305, 585],
                backgroundColor: [-15, -17, 5, 100, 305, 585].map(v => v < 0 ? C.rose + '70' : C.blue + '70'),
                borderColor: [-15, -17, 5, 100, 305, 585].map(v => v < 0 ? C.rose : C.blue),
                borderWidth: 1, borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Cumulative Cash Flow (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: { display: false }
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}

// ============================================================
// METRICS — CAC vs LTV Trend
// ============================================================
const cacLtvEl = document.getElementById('cacLtvChart');
if (cacLtvEl) {
    new Chart(cacLtvEl, {
        type: 'line',
        data: {
            labels: ['Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5'],
            datasets: [{
                label: 'LTV (₹ Lakhs)',
                data: [18, 30, 45, 54, 60],
                borderColor: C.blue, backgroundColor: C.blue + '08',
                borderWidth: 2.5, fill: true, tension: 0.4,
                pointRadius: 5, pointBackgroundColor: C.blue, pointBorderColor: '#151e2e', pointBorderWidth: 2
            }, {
                label: 'CAC (₹ Lakhs)',
                data: [5, 3.5, 3, 2.5, 2],
                borderColor: C.rose, backgroundColor: C.rose + '08',
                borderWidth: 2.5, fill: true, tension: 0.4,
                pointRadius: 5, pointBackgroundColor: C.rose, pointBorderColor: '#151e2e', pointBorderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Customer LTV vs CAC Trend (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}

// ============================================================
// METRICS — ARPU Growth
// ============================================================
const arpuEl = document.getElementById('arpuChart');
if (arpuEl) {
    new Chart(arpuEl, {
        type: 'bar',
        data: {
            labels: ['Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5'],
            datasets: [{
                label: 'ARPU (₹ Lakhs/year)',
                data: [6, 9.2, 12.5, 15, 18],
                backgroundColor: C.blue + '80',
                borderColor: C.blue,
                borderWidth: 1, borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Average Revenue Per Customer (₹ Lakhs/year)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: { display: false }
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { beginAtZero: true, grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}

// ============================================================
// COMPETITION — Pricing Comparison Bar
// ============================================================
const pricingCompEl = document.getElementById('pricingCompChart');
if (pricingCompEl) {
    new Chart(pricingCompEl, {
        type: 'bar',
        data: {
            labels: ['CYPHRA\nSOC', 'CYPHRA\nFull', 'Quick Heal\nEnterprise', 'CrowdStrike\nFalcon', 'Palo Alto\nCortex', 'Splunk\nEnterprise'],
            datasets: [{
                label: 'Annual Cost (₹ Lakhs)',
                data: [6, 36, 3, 45, 55, 35],
                backgroundColor: [C.blue, C.blue, C.amber, C.rose, C.rose, C.rose],
                borderWidth: 0, borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Annual Pricing Comparison (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: { display: false }
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted, font: { size: 10 } } },
                y: { beginAtZero: true, grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}

// ============================================================
// COMPETITION — Radar Chart
// ============================================================
const radarEl = document.getElementById('radarChart');
if (radarEl) {
    new Chart(radarEl, {
        type: 'radar',
        data: {
            labels: ['ML Threat Detection', 'Post-Quantum Crypto', 'Encrypted Comms', 'On-Premise Deploy', 'Pricing (Affordable)', 'Indian Made', 'Defence Features'],
            datasets: [{
                label: 'CYPHRA',
                data: [95, 100, 100, 100, 90, 100, 100],
                borderColor: C.blue, backgroundColor: C.blue + '18',
                borderWidth: 2, pointRadius: 3, pointBackgroundColor: C.blue
            }, {
                label: 'CrowdStrike',
                data: [90, 10, 10, 20, 20, 0, 30],
                borderColor: C.rose, backgroundColor: C.rose + '10',
                borderWidth: 2, pointRadius: 3, pointBackgroundColor: C.rose
            }, {
                label: 'Quick Heal',
                data: [40, 0, 0, 80, 85, 100, 10],
                borderColor: C.amber, backgroundColor: C.amber + '10',
                borderWidth: 2, pointRadius: 3, pointBackgroundColor: C.amber
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Competitive Feature Comparison', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                r: {
                    angleLines: { color: C.gridLine },
                    grid: { color: C.gridLine },
                    pointLabels: { color: C.muted, font: { size: 10 } },
                    ticks: { display: false },
                    suggestedMin: 0, suggestedMax: 100
                }
            }
        }
    });
}

// ============================================================
// FINANCIALS — Profit Margins Line
// ============================================================
const marginsEl = document.getElementById('marginsChart');
if (marginsEl) {
    new Chart(marginsEl, {
        type: 'line',
        data: {
            labels: ['Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5'],
            datasets: [{
                label: 'Gross Margin %',
                data: [78, 85, 89, 91, 92],
                borderColor: C.blue, borderWidth: 2, tension: 0.4,
                pointRadius: 5, pointBackgroundColor: C.blue, pointBorderColor: '#151e2e', pointBorderWidth: 2
            }, {
                label: 'EBITDA Margin %',
                data: [-110, -4, 21, 35, 40],
                borderColor: C.sky, borderWidth: 2, tension: 0.4,
                pointRadius: 5, pointBackgroundColor: C.sky, pointBorderColor: '#151e2e', pointBorderWidth: 2
            }, {
                label: 'Net Margin %',
                data: [-111, -4.2, 17, 29, 34],
                borderColor: C.purple, borderWidth: 2, tension: 0.4,
                pointRadius: 5, pointBackgroundColor: C.purple, pointBorderColor: '#151e2e', pointBorderWidth: 2
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Profit Margins Over Time (%)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { grid: defaultGrid, ticks: { color: C.muted, callback: v => v + '%' } }
            }
        }
    });
}

// ============================================================
// FINANCIALS — Revenue vs Expenses
// ============================================================
const revExpEl = document.getElementById('revExpChart');
if (revExpEl) {
    new Chart(revExpEl, {
        type: 'bar',
        data: {
            labels: ['Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5'],
            datasets: [{
                label: 'Revenue',
                data: [18, 120, 450, 800, 1200],
                backgroundColor: C.blue + '80', borderColor: C.blue, borderWidth: 1, borderRadius: 4
            }, {
                label: 'Total Expenses',
                data: [38, 125, 355, 520, 720],
                backgroundColor: C.rose + '50', borderColor: C.rose, borderWidth: 1, borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Revenue vs Total Expenses (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}

// ============================================================
// EXIT — Valuation Scenarios Bar
// ============================================================
const valuationEl = document.getElementById('valuationChart');
if (valuationEl) {
    new Chart(valuationEl, {
        type: 'bar',
        data: {
            labels: ['Conservative\n(8x Revenue)', 'Base Case\n(10x Revenue)', 'Optimistic\n(15x Revenue)'],
            datasets: [{
                label: 'Valuation (₹ Crore)',
                data: [48, 60, 90],
                backgroundColor: [C.amber + '80', C.blue + '80', C.emerald + '80'],
                borderColor: [C.amber, C.blue, C.emerald],
                borderWidth: 1, borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Year 5 Valuation Scenarios (₹ Crore)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: { display: false }
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { beginAtZero: true, grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + ' Cr' } }
            }
        }
    });
}

// ============================================================
// EXIT — Valuation Growth Over Time
// ============================================================
const valGrowthEl = document.getElementById('valGrowthChart');
if (valGrowthEl) {
    new Chart(valGrowthEl, {
        type: 'line',
        data: {
            labels: ['Year 1', 'Year 2', 'Year 3', 'Year 4', 'Year 5', 'Year 7'],
            datasets: [{
                label: 'Revenue Multiple (10x)',
                data: [1.8, 12, 45, 80, 120, 200],
                borderColor: C.blue, backgroundColor: C.blue + '08',
                borderWidth: 2, fill: true, tension: 0.4
            }, {
                label: 'EBITDA Multiple (15x)',
                data: [0, 0, 14.3, 42, 72, 135],
                borderColor: C.sky, backgroundColor: C.sky + '08',
                borderWidth: 2, fill: true, tension: 0.4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                title: { display: true, text: 'Valuation Growth Over Time (₹ Lakhs)', font: { size: 15, weight: '600' }, color: C.text, padding: { bottom: 16 } },
                legend: defaultLegend
            },
            scales: {
                x: { grid: defaultGrid, ticks: { color: C.muted } },
                y: { grid: defaultGrid, ticks: { color: C.muted, callback: v => '₹' + v + 'L' } }
            }
        }
    });
}
