// routes/tasks.js - Task Management Routes
const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const { pool } = require('../server');
const { authenticateToken } = require('../middleware/auth');

// All task routes require authentication
router.use(authenticateToken);

// ============================================
// GET ALL TASKS FOR USER
// ============================================
router.get('/', async (req, res) => {
  try {
    const { date, startDate, endDate } = req.query;
    let query = 'SELECT * FROM tasks WHERE user_id = $1';
    let params = [req.user.userId];

    // Filter by specific date
    if (date) {
      query += ' AND date = $2';
      params.push(date);
    }
    // Filter by date range
    else if (startDate && endDate) {
      query += ' AND date BETWEEN $2 AND $3';
      params.push(startDate, endDate);
    }

    query += ' ORDER BY date ASC, time ASC';

    const result = await pool.query(query, params);

    res.json({
      success: true,
      tasks: result.rows
    });

  } catch (error) {
    console.error('Get tasks error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch tasks'
    });
  }
});

// ============================================
// GET SINGLE TASK
// ============================================
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'SELECT * FROM tasks WHERE id = $1 AND user_id = $2',
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    res.json({
      success: true,
      task: result.rows[0]
    });

  } catch (error) {
    console.error('Get task error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch task'
    });
  }
});

// ============================================
// CREATE TASK
// ============================================
router.post('/',
  [
    body('title').trim().notEmpty().withMessage('Title is required'),
    body('date').isISO8601().withMessage('Valid date is required'),
    body('time').matches(/^([01]\d|2[0-3]):([0-5]\d)$/).withMessage('Valid time is required'),
    body('duration').isInt({ min: 5, max: 1440 }).withMessage('Duration must be 5-1440 minutes'),
    body('category').trim().notEmpty(),
    body('icon').trim().notEmpty(),
    body('color').matches(/^#[0-9A-F]{6}$/i).withMessage('Valid hex color required'),
    body('energyCost').isInt({ min: 1, max: 10 }).withMessage('Energy cost must be 1-10')
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: errors.array()[0].msg
        });
      }

      const { title, date, time, duration, category, icon, color, energyCost } = req.body;

      const result = await pool.query(
        `INSERT INTO tasks (
          user_id, title, date, time, duration, 
          category, icon, color, energy_cost
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *`,
        [req.user.userId, title, date, time, duration, category, icon, color, energyCost]
      );

      res.status(201).json({
        success: true,
        task: result.rows[0],
        message: 'Task created successfully! 💕'
      });

    } catch (error) {
      console.error('Create task error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to create task'
      });
    }
  }
);

// ============================================
// UPDATE TASK
// ============================================
router.put('/:id',
  [
    body('title').optional().trim().notEmpty(),
    body('date').optional().isISO8601(),
    body('time').optional().matches(/^([01]\d|2[0-3]):([0-5]\d)$/),
    body('duration').optional().isInt({ min: 5, max: 1440 }),
    body('color').optional().matches(/^#[0-9A-F]{6}$/i),
    body('energyCost').optional().isInt({ min: 1, max: 10 }),
    body('completed').optional().isBoolean()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          message: errors.array()[0].msg
        });
      }

      const { id } = req.params;
      const updates = req.body;

      // Verify task belongs to user
      const checkResult = await pool.query(
        'SELECT id FROM tasks WHERE id = $1 AND user_id = $2',
        [id, req.user.userId]
      );

      if (checkResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Task not found'
        });
      }

      // Build dynamic update query
      const fields = Object.keys(updates);
      const setClause = fields.map((field, index) => `${field} = $${index + 1}`).join(', ');
      const values = fields.map(field => updates[field]);
      values.push(id, req.user.userId);

      const result = await pool.query(
        `UPDATE tasks 
         SET ${setClause}, updated_at = NOW() 
         WHERE id = $${values.length - 1} AND user_id = $${values.length}
         RETURNING *`,
        values
      );

      res.json({
        success: true,
        task: result.rows[0],
        message: 'Task updated successfully! ✨'
      });

    } catch (error) {
      console.error('Update task error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update task'
      });
    }
  }
);

// ============================================
// TOGGLE TASK COMPLETION
// ============================================
router.patch('/:id/toggle', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE tasks 
       SET completed = NOT completed, updated_at = NOW()
       WHERE id = $1 AND user_id = $2
       RETURNING *`,
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    const task = result.rows[0];
    const message = task.completed 
      ? 'Great job! Task completed! 🎉' 
      : 'Task marked as incomplete';

    res.json({
      success: true,
      task: task,
      message: message
    });

  } catch (error) {
    console.error('Toggle task error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to toggle task'
    });
  }
});

// ============================================
// DELETE TASK
// ============================================
router.delete('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2 RETURNING id',
      [id, req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Task not found'
      });
    }

    res.json({
      success: true,
      message: 'Task deleted successfully'
    });

  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete task'
    });
  }
});

// ============================================
// GET TASK STATISTICS
// ============================================
router.get('/stats/summary', async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    let query = `
      SELECT 
        COUNT(*) as total_tasks,
        COUNT(*) FILTER (WHERE completed = true) as completed_tasks,
        SUM(energy_cost) FILTER (WHERE completed = true) as total_energy_earned,
        COUNT(DISTINCT date) as active_days
      FROM tasks 
      WHERE user_id = $1
    `;
    
    let params = [req.user.userId];

    if (startDate && endDate) {
      query += ' AND date BETWEEN $2 AND $3';
      params.push(startDate, endDate);
    }

    const result = await pool.query(query, params);

    res.json({
      success: true,
      stats: result.rows[0]
    });

  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch statistics'
    });
  }
});

module.exports = router;
