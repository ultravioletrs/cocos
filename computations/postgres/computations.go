package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/cocos/computations"
	db "github.com/ultravioletrs/cocos/internal/db"
)

const (
	errInvalid    = "invalid_text_representation"
	errTruncation = "string_data_right_truncation"
	errDuplicate  = "unique_violation"
)

var _ computations.Repository = (*computationRepo)(nil)

type computationRepo struct {
	db db.Database
}

func NewRepository(db db.Database) computations.Repository {
	return computationRepo{
		db: db,
	}
}

func (repo computationRepo) Save(ctx context.Context, c computations.Computation) (string, error) {
	q := `INSERT INTO computations (id, name, description, status, owner, start_time, end_time, datasets, algorithms, dataset_providers, algorithm_providers, ttl, metadata)
	VALUES (:id, :name, :description, :status, :owner, :start_time, :end_time, :datasets, :algorithms, :dataset_providers, :algorithm_providers, :ttl, :metadata) RETURNING id`
	comp, err := fromComputation(c)
	if err != nil {
		return "", err
	}
	row, err := repo.db.NamedQueryContext(ctx, q, comp)
	if err != nil {
		pqErr, ok := err.(*pq.Error)
		if ok {
			switch pqErr.Code.Name() {
			case errInvalid, errTruncation:
				return "", errors.Wrap(errors.ErrMalformedEntity, err)
			case errDuplicate:
				return "", errors.Wrap(errors.ErrConflict, err)
			}
		}
		return "", errors.Wrap(errors.ErrCreateEntity, err)
	}

	defer row.Close()
	row.Next()
	var id string
	if err := row.Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}

func (repo computationRepo) View(ctx context.Context, id string) (computations.Computation, error) {
	q := `SELECT id, name, description, status, owner, start_time, end_time, datasets, 
				algorithms, dataset_providers, algorithm_providers, ttl, metadata
				FROM computations
				WHERE id = $1`

	c := computation{
		ID: id,
	}

	if err := repo.db.QueryRowxContext(ctx, q, id).StructScan(&c); err != nil {
		if err == sql.ErrNoRows {
			return computations.Computation{}, errors.Wrap(errors.ErrNotFound, err)

		}
		return computations.Computation{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	return toComputation(c)
}

func (repo computationRepo) RetrieveAll(ctx context.Context, owner string, pm computations.PageMetadata) (computations.Page, error) {
	nq, name := getNameQuery(pm.Name)
	oq := getOrderQuery(pm.Order)
	dq := getDirQuery(pm.Dir)
	m, mq, err := getMetadataQuery(pm.Metadata)
	if err != nil {
		return computations.Page{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	var query []string
	if mq != "" {
		query = append(query, mq)
	}
	if nq != "" {
		query = append(query, nq)
	}

	var whereClause string
	if len(query) > 0 {
		whereClause = fmt.Sprintf(" WHERE %s", strings.Join(query, " AND "))
	}

	q := `SELECT id, name, description, status, owner, start_time, end_time, datasets, 
				algorithms, dataset_providers, algorithm_providers, ttl, metadata
				FROM computations %s
				ORDER BY %s %s LIMIT :limit OFFSET :offset`

	q = fmt.Sprintf(q, whereClause, oq, dq)
	params := map[string]interface{}{
		"owner":    owner,
		"limit":    pm.Limit,
		"offset":   pm.Offset,
		"name":     name,
		"metadata": m,
	}

	rows, err := repo.db.NamedQueryContext(ctx, q, params)
	if err != nil {
		return computations.Page{}, errors.Wrap(errors.ErrViewEntity, err)
	}
	defer rows.Close()

	var items []computations.Computation
	for rows.Next() {
		dbc := computation{Owner: owner}
		if err := rows.StructScan(&dbc); err != nil {
			return computations.Page{}, errors.Wrap(errors.ErrViewEntity, err)
		}

		c, err := toComputation(dbc)
		if err != nil {
			return computations.Page{}, err
		}

		items = append(items, c)
	}

	cq := fmt.Sprintf(`SELECT COUNT(*) FROM computations %s;`, whereClause)

	total, err := repo.total(ctx, cq, params)
	if err != nil {
		return computations.Page{}, errors.Wrap(errors.ErrViewEntity, err)
	}

	page := computations.Page{
		Computations: items,
		PageMetadata: computations.PageMetadata{
			Total:  total,
			Offset: pm.Offset,
			Limit:  pm.Limit,
			Order:  pm.Order,
			Dir:    pm.Dir,
		},
	}

	return page, nil
}

func (repo computationRepo) Update(ctx context.Context, c computations.Computation) error {
	q := `UPDATE computation SET name = :name, metadata = :metadata WHERE id = :id;`

	dbcpt, err := toDBComputation(c)
	if err != nil {
		return errors.Wrap(errors.ErrUpdateEntity, err)
	}

	res, errdb := repo.db.NamedExecContext(ctx, q, dbcpt)
	if errdb != nil {
		pqErr, ok := errdb.(*pq.Error)
		if ok {
			switch pqErr.Code.Name() {
			case errInvalid, errTruncation:
				return errors.Wrap(errors.ErrMalformedEntity, errdb)
			}
		}

		return errors.Wrap(errors.ErrUpdateEntity, errdb)
	}

	cnt, errdb := res.RowsAffected()
	if errdb != nil {
		return errors.Wrap(errors.ErrUpdateEntity, errdb)
	}

	if cnt == 0 {
		return errors.ErrNotFound
	}

	return nil
}

func (repo computationRepo) Delete(ctx context.Context, id string) error {
	q := `DELETE FROM computations WHERE id = :id`

	c := computation{
		ID: id,
	}

	if _, err := repo.db.NamedExecContext(ctx, q, c); err != nil {
		if err == sql.ErrNoRows {
			return errors.Wrap(errors.ErrNotFound, err)

		}
		return errors.Wrap(errors.ErrViewEntity, err)
	}

	return nil
}

func (repo computationRepo) total(ctx context.Context, query string, params interface{}) (uint64, error) {
	rows, err := repo.db.NamedQueryContext(ctx, query, params)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	total := uint64(0)
	if rows.Next() {
		if err := rows.Scan(&total); err != nil {
			return 0, err
		}
	}
	return total, nil
}

type computation struct {
	ID                 string         `db:"id"`
	Name               string         `db:"name"`
	Description        string         `db:"description"`
	Status             string         `db:"status"`
	Owner              string         `db:"owner"`
	StartTime          time.Time      `db:"start_time"`
	EndTime            time.Time      `db:"end_time"`
	Datasets           pq.StringArray `db:"datasets"`
	Algorithms         pq.StringArray `db:"algorithms"`
	DatasetProviders   pq.StringArray `db:"dataset_providers"`
	AlgorithmProviders pq.StringArray `db:"algorithm_providers"`
	Ttl                int            `db:"ttl"`
	Metadata           []byte         `db:"metadata"`
}

func toComputation(c computation) (computations.Computation, error) {
	var metadata map[string]interface{}
	if c.Metadata != nil {
		if err := json.Unmarshal([]byte(c.Metadata), &metadata); err != nil {
			return computations.Computation{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
	}
	ret := computations.Computation{
		ID:                 c.ID,
		Name:               c.Name,
		Description:        c.Description,
		Status:             c.Status,
		Owner:              c.Owner,
		StartTime:          c.StartTime,
		EndTime:            c.EndTime,
		Datasets:           c.Datasets,
		Algorithms:         c.Algorithms,
		DatasetProviders:   c.DatasetProviders,
		AlgorithmProviders: c.AlgorithmProviders,
		Ttl:                c.Ttl,
		Metadata:           metadata,
	}
	return ret, nil
}

func fromComputation(c computations.Computation) (computation, error) {
	metadata := []byte("{}")
	if len(c.Metadata) > 0 {
		b, err := json.Marshal(c.Metadata)
		if err != nil {
			return computation{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
		metadata = b
	}
	ret := computation{
		ID:                 c.ID,
		Name:               c.Name,
		Description:        c.Description,
		Status:             c.Status,
		Owner:              c.Owner,
		StartTime:          c.StartTime,
		EndTime:            c.EndTime,
		Datasets:           c.Datasets,
		Algorithms:         c.Algorithms,
		DatasetProviders:   c.DatasetProviders,
		AlgorithmProviders: c.AlgorithmProviders,
		Ttl:                c.Ttl,
		Metadata:           metadata,
	}
	return ret, nil
}

func getNameQuery(name string) (string, string) {
	if name == "" {
		return "", ""
	}
	name = fmt.Sprintf(`%%%s%%`, strings.ToLower(name))
	nq := `LOWER(name) LIKE :name`
	return nq, name
}

func getOrderQuery(order string) string {
	switch order {
	case "name":
		return "name"
	default:
		return "id"
	}
}

func getConnOrderQuery(order string, level string) string {
	switch order {
	case "name":
		return level + ".name"
	default:
		return level + ".id"
	}
}

func getDirQuery(dir string) string {
	switch dir {
	case "asc":
		return "ASC"
	default:
		return "DESC"
	}
}

func getMetadataQuery(m computations.Metadata) ([]byte, string, error) {
	mq := ""
	mb := []byte("{}")
	if len(m) > 0 {
		mq = `metadata @> :metadata`

		b, err := json.Marshal(m)
		if err != nil {
			return nil, "", err
		}
		mb = b
	}
	return mb, mq, nil
}

type dbComputation struct {
	ID       string `db:"id"`
	Owner    string `db:"owner"`
	Name     string `db:"name"`
	Metadata []byte `db:"metadata"`
}

func toDBComputation(th computations.Computation) (dbComputation, error) {
	data := []byte("{}")
	if len(th.Metadata) > 0 {
		b, err := json.Marshal(th.Metadata)
		if err != nil {
			return dbComputation{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
		data = b
	}

	return dbComputation{
		ID:       th.ID,
		Owner:    th.Owner,
		Name:     th.Name,
		Metadata: data,
	}, nil
}
